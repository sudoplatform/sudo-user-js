import AWSCore from 'aws-sdk/lib/core'
import AWSCognitoIdentityServiceProvider from 'aws-sdk/clients/cognitoidentityserviceprovider'
import { Config } from '../core/sdk-config'
import { apiKeyNames } from '../core/api-key-names'
import { AuthenticationStore } from '../core/auth-store'
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
}

export class CognitoUserPoolIdentityProvider implements IdentityProvider {
  private idpService: AWSCognitoIdentityServiceProvider
  private refreshTokenLifetime: number
  private logger: Logger

  constructor(
    private authenticationStore: AuthenticationStore,
    private keyManager: KeyManager,
    private config: Config,
    logger: Logger,
  ) {
    this.idpService = this.initCognitoIdpService()

    const refreshTokenLifetime = this.config.identityService
      .refreshTokenLifetime
    this.refreshTokenLifetime = refreshTokenLifetime ?? 60
    this.logger = logger
  }

  private initCognitoIdpService(): AWSCognitoIdentityServiceProvider {
    /** AWS credentials must be supplied to SDK, but are not actually used` */
    const awsBlankCredentials = {
      accessKeyId: '',
      secretAccessKey: '',
    }

    const idpService = new AWSCognitoIdentityServiceProvider({
      region: this.config.identityService.region,
      credentials: new AWSCore.Credentials(awsBlankCredentials),
    })

    return idpService
  }

  public async globalSignOut(accessToken: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const params = {
        AccessToken: accessToken,
      }

      this.idpService.globalSignOut(params, (error, data) => {
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
      const response = await this.idpService
        .signUp({
          ValidationData: validationData,
          Username: uid,
          Password: `@FF57&Z1)123!-${v4()}`,
          ClientId: this.config.identityService.clientId,
        })
        .promise()

      if (response.UserConfirmed) {
        this.logger.info('User successfully signed up.', { uid })
        return uid
      } else {
        throw new UserNotConfirmedError()
      }
    } catch (err) {
      const errorMsg = err.message
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
      const initiateAuthResult = await this.idpService
        .initiateAuth({
          ClientId: this.config.identityService.clientId,
          AuthFlow: 'CUSTOM_AUTH',
          AuthParameters: {
            USERNAME: userId,
          },
        })
        .promise()

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

        const respondToAuthChallengeResult = await this.idpService
          .respondToAuthChallenge({
            Session: session,
            ClientId: this.config.identityService.clientId,
            ChallengeName: challengeName,
            ChallengeResponses: {
              USERNAME: userId,
              ANSWER: answer,
            },
          })
          .promise()

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
      const initiateAuthResult = await this.idpService
        .initiateAuth({
          ClientId: this.config.identityService.clientId,
          AuthFlow: 'CUSTOM_AUTH',
          AuthParameters: {
            USERNAME: userId,
          },
        })
        .promise()

      const challengeName = initiateAuthResult.ChallengeName
      const session = initiateAuthResult.Session

      if (challengeName && session) {
        const respondToAuthChallengeResult = await this.idpService
          .respondToAuthChallenge({
            Session: session,
            ClientId: this.config.identityService.clientId,
            ChallengeName: challengeName,
            ChallengeResponses: {
              USERNAME: userId,
              ANSWER: token,
            },
            ClientMetadata: { challengeType: type },
          })
          .promise()

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
      const initiateAuthResult = await this.idpService
        .initiateAuth({
          ClientId: this.config.identityService.clientId,
          AuthFlow: 'REFRESH_TOKEN_AUTH',
          AuthParameters: {
            REFRESH_TOKEN: refreshToken,
          },
        })
        .promise()

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
    })
  }

  private async storeRefreshTokenLifetime(
    refreshTokenLifetime: number,
  ): Promise<void> {
    const tokenLifetime =
      refreshTokenLifetime * 24 * 60 * 60 * 1000 + new Date().getTime()
    await this.authenticationStore.setItem(
      apiKeyNames.refreshTokenExpiry,
      tokenLifetime.toString(),
    )
  }
}
