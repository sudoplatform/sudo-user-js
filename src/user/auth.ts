import { CognitoAuth } from 'amazon-cognito-auth-js'
import AWSCore from 'aws-sdk/lib/core'
import AWSCognitoIdentityServiceProvider from 'aws-sdk/clients/cognitoidentityserviceprovider'
import { Config } from '../core/sdk-config'
import { apiKeyNames } from '../core/api-key-names'
import { AuthenticationStore } from '../core/auth-store'
import { AuthenticationTokens } from './user-client'
import { KeyManager } from '../core/key-manager'
import { Subscriber } from '../core/subscriber'
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
import {
  createResolvablePromise,
  ResolvablePromise,
} from '../utils/resolvable-promise'

export interface AuthUI {
  /**
   * Presents the sign in UI for federated sign in using an external identity provider.
   */
  presentFederatedSignInUI(): void
  /**
   * Processes tokens from federated sign in that are returned in exchange
   * for the authorization code that is returned to the specified URL.
   *
   * @param url callback URL containing the authorization code.
   * @return Successful authentication result AuthenticationTokens.
   */
  processFederatedSignInTokens(url: string): Promise<AuthenticationTokens>
  /**
   * Returns the ID token cached from the last sign-in.
   *
   * @return ID token.
   */
  getIdToken(): string | undefined
  /**
   * Returns the access token cached from the last sign-in.
   *
   * @return access token.
   */
  getAccessToken(): string | undefined
  /**
   * Returns the refresh token cached from the last sign-in.
   *
   * @return refresh token.
   */
  getRefreshToken(): string | undefined
  /**
   * Returns the ID and access token expiry cached from the last sign-in.
   *
   * @return token expiry.
   */
  getTokenExpiry(): Date | undefined
  /**
   * Returns the refresh token expiry cached from the last sign-in.
   *
   * @return refresh token expiry.
   */
  getRefreshTokenExpiry(): Date | undefined
  /**
   * Retrieve ID token, access token, refresh token and token expiry cached from the last sign-in.
   *
   * @return AuthenticationTokens cached from the last sign-in
   */
  getAuthTokens(): AuthenticationTokens | undefined

  /**
   * Indicates whether or not this client is signed in with Sudo Platform backend. The client is
   * considered signed in if it cached valid ID, access and refresh tokens.
   *
   * @return *true* if the client is signed in.
   */
  isSignedIn(): Promise<boolean>
  /**
   * Refresh the access and ID tokens using the refresh token.
   *
   * @param refreshToken refresh token used to refresh the access and ID tokens.
   * @return Successful authentication result AuthenticationTokens containing refreshed tokens
   */
  refreshTokens(refreshToken: string): Promise<AuthenticationTokens>
  /**
   * Retrieves the latest ID token. This is to be used by the AWS AppSync client.
   *
   * @returns the latest ID token
   */
  getLatestAuthToken(): Promise<string>
  /**
   * Returns the user name associated with this client. The username maybe needed to contact
   * the support team when diagnosing an issue related to a specific user.
   *
   * @return user name.
   */
  getUserName(): string | undefined
  /**
   * Signs out the user from all devices.
   *
   * @param accessToken access token used to authorize the request.
   */
  globalSignOut(accessToken: string): Promise<void>
  /**
   * Resets any internal state.
   */
  reset(): void
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
   * Presents the Cognito hosted UI signout endpoint.
   * When the endpoint is invoked, the hosted web app's cookies
   * will be invalidated, but the user is not logged out of Cognito.
   */
  presentSignOutUI(): void
}

export class CognitoAuthUI implements AuthUI, Subscriber {
  private auth: CognitoAuth
  private idpService: AWSCognitoIdentityServiceProvider
  private tokensRefreshedPromise?: ResolvablePromise<AuthenticationTokens>
  private refreshTokenLifetime: number
  private logger: Logger

  constructor(
    private authenticationStore: AuthenticationStore,
    private keyManager: KeyManager,
    private config: Config,
    logger: Logger,
    private launchUriFn?: (url: string) => void,
  ) {
    this.authenticationStore.subscribe(this)
    this.auth = this.initCognitoAuthSDK()
    this.idpService = this.initCognitoIdpService()

    const refreshTokenLifetime = this.config.federatedSignIn
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

  private initCognitoAuthSDK(): CognitoAuth {
    const cognitoAuthConfig = {
      ClientId: this.config.federatedSignIn.appClientId,
      AppWebDomain: this.config.federatedSignIn.webDomain,
      IdentityProvider: this.config.federatedSignIn.identityProvider,
      RedirectUriSignIn: this.config.federatedSignIn.signInRedirectUri,
      RedirectUriSignOut: this.config.federatedSignIn.signOutRedirectUri,
      TokenScopesArray: ['openid', 'aws.cognito.signin.user.admin'],
      Storage: this.authenticationStore,
      LaunchUri: this.launchUriFn,
    }

    const auth = new CognitoAuth(cognitoAuthConfig)
    auth.useCodeGrantFlow()

    auth.userhandler = {
      onSuccess: (result) => {
        this.logger.info({ result }, 'Successfully signed in.')
      },

      onFailure: (error) => {
        this.logger.error(new AuthenticationError(error).message)
      },
    }
    return auth
  }

  presentFederatedSignInUI(): void {
    this.auth.getSession()
  }

  async processFederatedSignInTokens(
    url: string,
  ): Promise<AuthenticationTokens> {
    this.tokensRefreshedPromise = createResolvablePromise<
      AuthenticationTokens
    >()
    this.auth.parseCognitoWebResponse(url)
    const authTokens = await this.tokensRefreshedPromise
    await this.storeRefreshTokenLifetime(this.refreshTokenLifetime)
    return authTokens
  }
  /**
   * This function is called when the key manager notifies subscribers of an item update.
   *
   * @param itemName the name of the item being updated
   */
  update(itemName: string): void {
    if (itemName === 'idToken') {
      const authTokens = this.getAuthTokens()
      if (authTokens) {
        this.tokensRefreshedPromise?.resolve(authTokens)
      }
    }
    this.logger.info('Updated: ', itemName)
  }

  getAuthTokens(): AuthenticationTokens | undefined {
    const idToken = this.getIdToken()
    const accessToken = this.getAccessToken()
    const refreshToken = this.getRefreshToken()
    const tokenExpiry = this.getTokenExpiry()

    if (idToken && accessToken && refreshToken && tokenExpiry) {
      return {
        idToken: idToken,
        accessToken: accessToken,
        refreshToken: refreshToken,
        tokenExpiry: tokenExpiry.getTime(),
      }
    } else {
      return undefined
    }
  }

  getIdToken(): string | undefined {
    return this.authenticationStore.getItem(apiKeyNames.idToken)
  }

  getAccessToken(): string | undefined {
    return this.authenticationStore.getItem(apiKeyNames.accessToken)
  }

  getRefreshToken(): string | undefined {
    return this.authenticationStore.getItem(apiKeyNames.refreshToken)
  }

  getTokenExpiry(): Date | undefined {
    const expiry = this.authenticationStore.getItem(apiKeyNames.tokenExpiry)
    return expiry ? new Date(Number(expiry) * 1000) : undefined
  }

  getRefreshTokenExpiry(): Date | undefined {
    let expiry = undefined
    const timeSinceEpoch = this.authenticationStore.getItem(
      apiKeyNames.refreshTokenExpiry,
    )
    if (timeSinceEpoch) {
      expiry = new Date(Number(timeSinceEpoch))
    }
    return expiry
  }

  getUserName(): string | undefined {
    return this.authenticationStore.getItem(apiKeyNames.userId)
  }

  async isSignedIn(): Promise<boolean> {
    const authTokens = this.getAuthTokens()
    const expiry = this.getRefreshTokenExpiry()
    if (
      authTokens &&
      authTokens.idToken &&
      authTokens.accessToken &&
      authTokens.refreshToken &&
      expiry &&
      // Considered signed in up to 1 hour before the expiry of refresh token.
      expiry.getTime() > new Date().getTime() + 60 * 60 * 1000
    ) {
      return true
    } else {
      this.authenticationStore.reset()
      return false
    }
  }

  async refreshTokens(refreshToken: string): Promise<AuthenticationTokens> {
    this.tokensRefreshedPromise = createResolvablePromise<
      AuthenticationTokens
    >()
    this.auth.refreshSession(refreshToken)
    const authTokens = await this.tokensRefreshedPromise
    return authTokens
  }

  async getLatestAuthToken(): Promise<string> {
    const idToken = this.getIdToken()
    const refreshToken = this.getRefreshToken()
    const expiry = this.getTokenExpiry()

    if (idToken && refreshToken && expiry) {
      if (expiry.getTime() > new Date().getTime() + 600 * 1000) {
        return idToken
      } else {
        const authTokens = await this.refreshTokens(refreshToken)
        return authTokens.idToken
      }
    } else {
      // If tokens are missing then it's likely due to the client not being signed in.
      throw new AuthenticationError('Client is not signed in.')
    }
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
          this.logger.info({ data }, 'User successfully signed out.')
          resolve()
        }
      })
    })
  }

  reset(): void {
    this.authenticationStore.reset()
    const cognitoAuthAny = this.auth as any
    cognitoAuthAny.clearCachedTokensScopes()
    cognitoAuthAny.signInUserSession = null
    cognitoAuthAny.signInUserSession = cognitoAuthAny.getCachedSession()
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
        this.logger.info({ uid }, 'User successfully signed up.')
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

  presentSignOutUI(): void {
    const signOutUrl = this.auth.getFQDNSignOut()
    this.auth.launchUri(signOutUrl)
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
