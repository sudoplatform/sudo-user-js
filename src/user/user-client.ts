import {
  AuthenticationError,
  DefaultConfigurationManager,
  DefaultLogger,
  DefaultSudoKeyManager,
  FatalError,
  Logger,
  NotAuthorizedError,
  NotRegisteredError,
  PublicKeyFormat,
  RegisterError,
  SudoKeyManager,
} from '@sudoplatform/sudo-common'
import { WebSudoCryptoProvider } from '@sudoplatform/sudo-web-crypto-provider'
import * as JWT from 'jsonwebtoken'
import { v4 } from 'uuid'
import { AuthenticationProvider } from '..'
import { ApiClient } from '../client/apiClient'
import { apiKeyNames } from '../core/api-key-names'
import { AuthenticationStore } from '../core/auth-store'
import { KeyManager, PublicKey } from '../core/key-manager'
import { Config } from '../core/sdk-config'
import { AuthUI, CognitoAuthUI } from './auth'
import { AlreadyRegisteredError } from './error'
import {
  CognitoUserPoolIdentityProvider,
  IdentityProvider,
} from './identity-provider'
import { AuthenticationTokens, SudoUserClient } from './user-client-interface'
import { userKeyNames } from './user-key-names'

export interface SudoUserOptions {
  authenticationStore?: AuthenticationStore
  sudoKeyManager?: SudoKeyManager
  authUI?: AuthUI
  identityProvider?: IdentityProvider
  apiClient?: ApiClient
  launchUriFn?: (url: string) => void
  config?: Config
  logger?: Logger
}

export class DefaultSudoUserClient implements SudoUserClient {
  private config: Config
  private keyManager: KeyManager
  private sudoUserKeyManager: SudoKeyManager
  private authenticationStore: AuthenticationStore
  private identityProvider: IdentityProvider
  private apiClient: ApiClient
  private logger: Logger
  private authUI?: AuthUI
  private launchUriFn?: (url: string) => void

  constructor(options?: SudoUserOptions) {
    this.logger = options?.logger ?? new DefaultLogger('SudoUser', 'warn')

    this.config =
      options?.config ??
      DefaultConfigurationManager.getInstance().bindConfigSet<Config>(
        Config,
        undefined,
      )

    this.authenticationStore =
      options?.authenticationStore ?? new AuthenticationStore()

    if (options?.sudoKeyManager) {
      this.sudoUserKeyManager = options?.sudoKeyManager
    } else {
      const cryptoProvider = new WebSudoCryptoProvider(
        'SudoUserClient',
        'com.sudoplatform.appservicename',
      )
      this.sudoUserKeyManager = new DefaultSudoKeyManager(cryptoProvider)
    }
    this.keyManager = new KeyManager(this.sudoUserKeyManager)

    this.launchUriFn = options?.launchUriFn

    this.identityProvider =
      options?.identityProvider ??
      new CognitoUserPoolIdentityProvider(
        this.authenticationStore,
        this.keyManager,
        this.config,
        this.logger,
      )

    const federatedSignInConfig = this.config?.federatedSignIn
    if (federatedSignInConfig) {
      this.authUI =
        options?.authUI ??
        new CognitoAuthUI(
          this.authenticationStore,
          federatedSignInConfig,
          this.logger,
          this.launchUriFn,
        )
    }

    this.apiClient =
      options?.apiClient ??
      new ApiClient(
        this.config.identityService.region,
        this.config.identityService.apiUrl,
        this,
        this.logger,
      )
  }

  public get sudoKeyManager(): SudoKeyManager {
    return this.sudoUserKeyManager
  }

  public presentFederatedSignInUI(): void {
    try {
      this.authUI?.presentFederatedSignInUI()
    } catch (error) {
      this.logger.error('Failed to launch the federated sign in UI.', { error })
      throw new AuthenticationError(error)
    }
  }

  public async processFederatedSignInTokens(
    url: string,
  ): Promise<AuthenticationTokens> {
    try {
      const authTokens = await this.authUI?.processFederatedSignInTokens(url)
      if (authTokens) {
        return authTokens
      } else {
        throw new AuthenticationError('Authentication tokens missing.')
      }
    } catch (error) {
      this.logger.error('Failed to process the federated sign in redirect.', {
        error,
      })
      throw new AuthenticationError(error)
    }
  }

  public getIdToken(): string | undefined {
    return this.authenticationStore.getItem(apiKeyNames.idToken)
  }

  public getAccessToken(): string | undefined {
    return this.authenticationStore.getItem(apiKeyNames.accessToken)
  }

  public getRefreshToken(): string | undefined {
    return this.authenticationStore.getItem(apiKeyNames.refreshToken)
  }

  public getTokenExpiry(): Date | undefined {
    const expiry = this.authenticationStore.getItem(apiKeyNames.tokenExpiry)
    return expiry ? new Date(Number(expiry) * 1000) : undefined
  }

  public getRefreshTokenExpiry(): Date | undefined {
    let expiry = undefined
    const timeSinceEpoch = this.authenticationStore.getItem(
      apiKeyNames.refreshTokenExpiry,
    )
    if (timeSinceEpoch) {
      expiry = new Date(Number(timeSinceEpoch))
    }
    return expiry
  }

  public getUserName(): string | undefined {
    return this.authenticationStore.getItem(apiKeyNames.userId)
  }

  public setUserName(name: string): void {
    this.keyManager.addString('userId', name)
  }

  getUserClaim(name: string): any | undefined {
    let claim = undefined
    const idToken = this.getIdToken()
    if (idToken) {
      const decoded: any = JWT.decode(idToken, { complete: true })
      if (decoded) {
        claim = decoded.payload[name]
      }
    }
    return claim
  }

  public getSubject(): string | undefined {
    return this.getUserClaim('sub')
  }

  public async isSignedIn(): Promise<boolean> {
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
    try {
      const uid = this.getUserName()
      if (uid) {
        const authTokens = await this.identityProvider.refreshTokens(
          refreshToken,
        )
        await this.storeTokens(uid, authTokens)
        return authTokens
      } else {
        throw new NotRegisteredError('Not registered.')
      }
    } catch (error) {
      throw new AuthenticationError(error)
    }
  }

  async getLatestAuthToken(): Promise<string> {
    const idToken = this.getIdToken()
    const refreshToken = this.getRefreshToken()
    const expiry = this.getTokenExpiry()

    if (idToken && refreshToken && expiry) {
      if (expiry.getTime() > new Date().getTime() + 600 * 1000) {
        return idToken
      } else {
        try {
          const authTokens = await this.refreshTokens(refreshToken)
          return authTokens.idToken
        } catch (error) {
          this.logger.info(
            'getLatestAuthToken: Token refresh failed',
            error.message,
          )
          // return an empty id token
          return ''
        }
      }
    } else {
      // If tokens are missing then it's likely due to the client not being signed in.
      // Return an empty id token
      return ''
    }
  }

  async globalSignOut(): Promise<void> {
    const accessToken = this.getAccessToken()
    if (accessToken) {
      await this.identityProvider.globalSignOut(accessToken)
      this.clearAuthenticationTokens()
    }
  }

  async registerWithAuthenticationProvider(
    authenticationProvider: AuthenticationProvider,
    registrationId?: string,
  ): Promise<string> {
    this.logger.info('Registering using an external authentication provider.')

    if (!(await this.isRegistered())) {
      const authInfo = await authenticationProvider.getAuthenticationInfo()

      if (!authInfo.isValid()) {
        throw new NotAuthorizedError(
          'Authentication provider returned invalid authentication info.',
        )
      }

      const token = authInfo.encode()
      const jwt: any = JWT.decode(token, { complete: true })
      let uid
      if (jwt && jwt.payload['sub']) {
        uid = jwt.payload['sub']
      } else {
        uid = v4()
      }

      const publicKey = await this.generateRegistrationData()

      const data = {
        challengeType: authInfo.type,
        answer: token,
        registrationId: registrationId ? registrationId : v4(),
        publicKey: JSON.stringify(publicKeyToRSAPublicKey(publicKey)),
      }

      const validationData = Object.keys(data).map((key): {
        Name: string
        Value: string
      } => {
        return {
          Name: key,
          Value: (data as any)[key],
        }
      })

      const userId = await this.identityProvider.register(uid, validationData)
      if (userId) {
        this.setUserName(userId)
        return userId
      } else {
        throw new RegisterError(
          'Registration was successful but not user ID was returned.',
        )
      }
    } else {
      throw new AlreadyRegisteredError()
    }
  }

  async signInWithAuthenticationProvider(
    authenticationProvider: AuthenticationProvider,
  ): Promise<AuthenticationTokens> {
    this.logger.info('Signing in using external authentication provider.')
    const authInfo = await authenticationProvider.getAuthenticationInfo()

    if (!authInfo.isValid()) {
      throw new NotAuthorizedError(
        'Authentication provider returned invalid authentication info.',
      )
    }

    const uid = authInfo.getUsername()
    const token = authInfo.encode()
    const type = authInfo.type

    const authTokens = await this.identityProvider.signInWithToken(
      uid,
      token,
      type,
    )
    await this.storeTokens(uid, authTokens)
    return authTokens
  }

  async isRegistered(): Promise<boolean> {
    try {
      const uid = await this.keyManager.getString('userId')
      return uid ? true : false
    } catch (err) {
      return false
    }
  }

  async signInWithKey(): Promise<AuthenticationTokens> {
    this.logger.info('Signing in using private key.')
    const uid = await this.keyManager.getString('userId')
    const userKeyId = await this.keyManager.getString('userKeyId')

    if (uid && userKeyId) {
      const authTokens = await this.identityProvider.signInWithKey(
        uid,
        userKeyId,
      )
      if (authTokens) {
        await this.storeTokens(uid, authTokens)
        return authTokens
      } else {
        throw new FatalError('Unexpected error. Unable to sign in.')
      }
    } else {
      throw new NotRegisteredError('Not registered.')
    }
  }

  async deregister(): Promise<void> {
    await this.apiClient.deregister()
    this.keyManager.reset()
    this.clearAuthenticationTokens()
  }

  clearAuthenticationTokens(): void {
    this.authenticationStore.reset()
    if (this.authUI) {
      this.authUI.reset()
    }
  }

  presentSignOutUI(): void {
    this.authUI?.presentSignOutUI()
  }

  reset(): void {
    this.keyManager.reset()
    this.apiClient.reset()
    this.clearAuthenticationTokens()
  }

  /**
   * Store the authentication tokens and user id of the signed in user. This function
   * is only called when a user has successfully signed in using a private key.
   */
  private async storeTokens(
    uid: string,
    authTokens: AuthenticationTokens,
  ): Promise<void> {
    await this.authenticationStore.setItem(apiKeyNames.userId, uid)
    await this.authenticationStore.setItem(
      apiKeyNames.idToken,
      authTokens.idToken,
    )
    await this.authenticationStore.setItem(
      apiKeyNames.accessToken,
      authTokens.accessToken,
    )
    await this.authenticationStore.setItem(
      apiKeyNames.refreshToken,
      authTokens.refreshToken,
    )
  }

  private async generateRegistrationData(): Promise<PublicKey> {
    const keyId = await this.keyManager.generateKeyPair()
    await this.keyManager.addString(userKeyNames.userKeyId, keyId)
    const publicKey = await this.keyManager.exportPublicKey(keyId)
    return publicKey
  }

  private getAuthTokens(): AuthenticationTokens | undefined {
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

  /**
   * Provide a custom auth UI. This is mainly used for unit testing (optional).
   */
  setAuthUI(authUI: AuthUI): void {
    this.authUI = authUI
  }

  /**
   * Provide a custom identity provider. This is mainly used for unit testing (optional).
   */
  setIdentityProvider(identityProvider: IdentityProvider): void {
    this.identityProvider = identityProvider
  }

  /**
   * Provide a custom function to open the sign in url.
   * This is mainly used for unit testing (optional).
   */
  setLaunchUriFn(launchUriFn: (url: string) => void): void {
    this.launchUriFn = launchUriFn
  }

  /**
   * Provide a custom authentication store.
   * This is mainly used for unit testing (optional).
   */
  setAuthenticationStore(authenticationStore: AuthenticationStore): void {
    this.authenticationStore = authenticationStore
  }
}

/**
 * Convert PublicKey of any format to an RSAPublicKey format public key
 *
 * @param publicKey PublicKey to convert
 * @returns RSAPublicKey formatted PublicKey
 */
function publicKeyToRSAPublicKey(publicKey: PublicKey): PublicKey {
  if (publicKey.keyFormat === PublicKeyFormat.RSAPublicKey) {
    return publicKey
  }

  return {
    ...publicKey,
    publicKey: publicKey.publicKey.replace(
      'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A',
      '',
    ),
    keyFormat: PublicKeyFormat.RSAPublicKey,
  }
}
