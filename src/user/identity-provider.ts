import {
  CognitoIdentityProviderClient,
  GlobalSignOutCommand,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
  RevokeTokenCommand,
  SignUpCommand,
} from '@aws-sdk/client-cognito-identity-provider'
import { Config } from '../core/sdk-config'
import { apiKeyNames } from '../core/api-key-names'
import { AuthenticationTokens } from './user-client-interface'
import { KeyManager } from '../core/key-manager'
import { v4 } from 'uuid'
import {
  AuthenticationError,
  NotAuthorizedError,
  SignOutError,
  ServiceError,
  FatalError,
  UserNotConfirmedError,
  Logger,
} from '@sudoplatform/sudo-common'
import { AlreadyRegisteredError } from './error'

export interface IdentityProvider {
  /**
   * Signs out the user from all devices.
   *
   * @param accessToken access token used to authorize the request.
   */
  globalSignOut(accessToken: string): Promise<void>
  /**
   * Registers a new user against the identity provider.
   *
   * @param uid user ID.
   * @param validationData registration parameters.
   * @return user ID
   */
  register(
    uid: string,
    validationData: { Name: string; Value: string }[],
  ): Promise<string>
  /**
   * Sign into the identity provider using a signing key.
   *
   * @param uid user ID.
   * @param keyId signing key id.
   * @return Successful authentication result AuthenticationTokens
   */
  signInWithKey(uid: string, keyId: string): Promise<AuthenticationTokens>

  /**
   * Sign into the identity provider using a token issued by an external
   * authentication provider.
   *
   * @param uid user ID.
   * @param token authentication token.
   * @param type token type.
   * @return Successful authentication result AuthenticationTokens
   */
  signInWithToken(
    uid: string,
    token: string,
    type: string,
  ): Promise<AuthenticationTokens>

  /**
   * Refresh the access and ID tokens using the refresh token.
   *
   * @param refreshToken refresh token used to refresh the access and ID tokens.
   * @return Successful authentication result AuthenticationTokens containing refreshed tokens
   */
  refreshTokens(refreshToken: string): Promise<AuthenticationTokens>

  /**
   * Signs out the user from this device.
   *
   * @param refreshToken refresh token to revoke to sign out this device.
   */
  signOut(refreshToken: string): Promise<void>
}

export class CognitoUserPoolIdentityProvider implements IdentityProvider {
  private idpService: CognitoIdentityProviderClient
  private refreshTokenLifetime: number
  private logger: Logger

  constructor(
    private keyManager: KeyManager,
    private config: Config,
    logger: Logger,
  ) {
    this.idpService = this.initCognitoIdpService()

    const refreshTokenLifetime =
      this.config.identityService.refreshTokenLifetime
    this.refreshTokenLifetime = refreshTokenLifetime ?? 60
    this.logger = logger
  }

  private initCognitoIdpService(): CognitoIdentityProviderClient {
    const idpService = new CognitoIdentityProviderClient({
      region: this.config.identityService.region,
    })

    return idpService
  }

  public async globalSignOut(accessToken: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const params = {
        AccessToken: accessToken,
      }

      const globalSignOut = new GlobalSignOutCommand(params)
      this.idpService.send(globalSignOut, (error, data) => {
        if (error) {
          this.logger.error(error.message)
          reject(new SignOutError(error.message))
        } else {
          this.logger.info('User successfully signed out.', { data })
          resolve()
        }
      })
    })
  }

  async register(
    uid: string,
    validationData: { Name: string; Value: string }[],
  ): Promise<string> {
    try {
      const signUp = new SignUpCommand({
        ValidationData: validationData,
        Username: uid,
        Password: `@FF57&Z1)123!-${v4()}`,
        ClientId: this.config.identityService.clientId,
      })
      const response = await this.idpService.send(signUp)

      if (response.UserConfirmed) {
        this.logger.info('User successfully signed up.', { uid })
        return uid
      } else {
        throw new UserNotConfirmedError()
      }
    } catch (err) {
      const error = err as Error
      const errorMsg = error.message
      if (errorMsg.includes('sudoplatform.ServiceError')) {
        throw new ServiceError(errorMsg)
      } else if (
        errorMsg.includes('sudoplatform.identity.UserValidationFailed') ||
        errorMsg.includes('sudoplatform.identity.TestRegCheckFailed')
      ) {
        throw new NotAuthorizedError(errorMsg)
      } else if (errorMsg.includes('sudoplatform.identity.AlreadyRegistered')) {
        throw new AlreadyRegisteredError()
      } else {
        throw new FatalError(errorMsg)
      }
    }
  }

  async signInWithKey(
    userId: string,
    keyId: string,
  ): Promise<AuthenticationTokens> {
    return new Promise(async (resolve, reject) => {
      const initiateAuthCommand = new InitiateAuthCommand({
        ClientId: this.config.identityService.clientId,
        AuthFlow: 'CUSTOM_AUTH',
        AuthParameters: {
          USERNAME: userId,
        },
      })
      const initiateAuthResult = await this.idpService.send(initiateAuthCommand)

      const challengeName = initiateAuthResult.ChallengeName
      const session = initiateAuthResult.Session
      const params = initiateAuthResult.ChallengeParameters

      if (
        params &&
        params['nonce'] &&
        params['audience'] &&
        challengeName &&
        session
      ) {
        const nonce = params['nonce']
        const audience = params['audience']

        const answer = await this.keyManager.signJWT(keyId, {
          jti: nonce,
          iss: userId,
          aud: audience,
          sub: userId,
          exp: Math.floor(+new Date() / 1000) + 300,
        })

        const respondToAuthChallenge = new RespondToAuthChallengeCommand({
          Session: session,
          ClientId: this.config.identityService.clientId,
          ChallengeName: challengeName,
          ChallengeResponses: {
            USERNAME: userId,
            ANSWER: answer,
          },
        })
        const respondToAuthChallengeResult = await this.idpService.send(
          respondToAuthChallenge,
        )

        const authResult = respondToAuthChallengeResult.AuthenticationResult
        const idToken = authResult?.IdToken
        const accessToken = authResult?.AccessToken
        const refreshToken = authResult?.RefreshToken
        const tokenExpiry = authResult?.ExpiresIn

        if (idToken && accessToken && refreshToken && tokenExpiry) {
          const authTokens = {
            idToken: idToken,
            accessToken: accessToken,
            refreshToken: refreshToken,
            tokenExpiry: tokenExpiry,
          }
          await this.storeRefreshTokenLifetime(this.refreshTokenLifetime)
          resolve(authTokens)
        } else {
          reject(new AuthenticationError('Authentication tokens not found.'))
        }
      } else {
        reject(new AuthenticationError('Invalid initiate auth result.'))
      }
    })
  }

  async signInWithToken(
    userId: string,
    token: string,
    type: string,
  ): Promise<AuthenticationTokens> {
    return new Promise(async (resolve, reject) => {
      const initiateAuth = new InitiateAuthCommand({
        ClientId: this.config.identityService.clientId,
        AuthFlow: 'CUSTOM_AUTH',
        AuthParameters: {
          USERNAME: userId,
        },
      })
      const initiateAuthResult = await this.idpService.send(initiateAuth)

      const challengeName = initiateAuthResult.ChallengeName
      const session = initiateAuthResult.Session

      if (challengeName && session) {
        const respondToAuthChallenge = new RespondToAuthChallengeCommand({
          Session: session,
          ClientId: this.config.identityService.clientId,
          ChallengeName: challengeName,
          ChallengeResponses: {
            USERNAME: userId,
            ANSWER: token,
          },
          ClientMetadata: { challengeType: type },
        })
        const respondToAuthChallengeResult = await this.idpService.send(
          respondToAuthChallenge,
        )

        const authResult = respondToAuthChallengeResult.AuthenticationResult
        const idToken = authResult?.IdToken
        const accessToken = authResult?.AccessToken
        const refreshToken = authResult?.RefreshToken
        const tokenExpiry = authResult?.ExpiresIn

        if (idToken && accessToken && refreshToken && tokenExpiry) {
          const authTokens = {
            idToken: idToken,
            accessToken: accessToken,
            refreshToken: refreshToken,
            tokenExpiry: tokenExpiry,
          }
          await this.storeRefreshTokenLifetime(this.refreshTokenLifetime)
          resolve(authTokens)
        } else {
          reject(new AuthenticationError('Authentication tokens not found.'))
        }
      } else {
        reject(new AuthenticationError('Invalid initiate auth result.'))
      }
    })
  }

  async refreshTokens(refreshToken: string): Promise<AuthenticationTokens> {
    return new Promise(async (resolve, reject) => {
      try {
        const initiateAuth = new InitiateAuthCommand({
          ClientId: this.config.identityService.clientId,
          AuthFlow: 'REFRESH_TOKEN_AUTH',
          AuthParameters: {
            REFRESH_TOKEN: refreshToken,
          },
        })
        const initiateAuthResult = await this.idpService.send(initiateAuth)

        const idToken = initiateAuthResult.AuthenticationResult?.IdToken
        const accessToken = initiateAuthResult.AuthenticationResult?.AccessToken
        const tokenExpiry = initiateAuthResult.AuthenticationResult?.ExpiresIn

        if (idToken && accessToken && tokenExpiry) {
          const authTokens = {
            idToken: idToken,
            accessToken: accessToken,
            refreshToken: refreshToken,
            tokenExpiry: tokenExpiry,
          }
          await this.storeRefreshTokenLifetime(this.refreshTokenLifetime)
          resolve(authTokens)
        } else {
          reject(new AuthenticationError('Authentication tokens not found.'))
        }
      } catch (err) {
        const error = err as Error
        reject(new AuthenticationError(error.message))
      }
    })
  }

  async signOut(refreshToken: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const params = {
        Token: refreshToken,
        ClientId: this.config.identityService.clientId,
      }

      const revokeToken = new RevokeTokenCommand(params)
      this.idpService.send(revokeToken, (error, data) => {
        if (error) {
          this.logger.error(error.message)
          reject(new SignOutError(error.message))
        } else {
          this.logger.info('User successfully signed out.', { data })
          resolve()
        }
      })
    })
  }

  private async storeRefreshTokenLifetime(
    refreshTokenLifetime: number,
  ): Promise<void> {
    const tokenLifetime =
      refreshTokenLifetime * 24 * 60 * 60 * 1000 + new Date().getTime()
    await this.keyManager.removeItem(apiKeyNames.refreshTokenExpiry)
    await this.keyManager.addString(
      apiKeyNames.refreshTokenExpiry,
      tokenLifetime.toString(),
    )
  }
}
