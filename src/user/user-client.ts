import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import * as JWT from 'jsonwebtoken'
import { AuthenticationStore } from '../core/auth-store'
import { Config } from '../core/sdk-config'
import { AuthUI, CognitoAuthUI } from './auth'
import { AuthenticationProvider } from './auth-provider'
import { v4 } from 'uuid'
import { KeyManager, PublicKey } from '../core/key-manager'
import { userKeyNames } from './user-key-names'
import {
  AuthenticationError,
  RegisterError,
  NotRegisteredError,
  FatalError,
} from '../errors/errors'
import { apiKeyNames } from '../core/api-key-names'
import { ApiClient } from '../client/apiClient'

/**
 * Encapsulates the authentication tokens obtained from a successful authentication.
 *
 * @param idToken ID token containing the user's identity attributes.
 * @param accessToken access token required for authorizing API access.
 * @param refreshToken refresh token used for refreshing ID and access tokens.
 * @param tokenExpiry expiry of ID and access tokens in milliseconds.
 */
export interface AuthenticationTokens {
  idToken: string
  accessToken: string
  refreshToken: string
  tokenExpiry: number
}

/**
 * Interface encapsulating a library of functions for calling Sudo Platform identity service,
 * handling federated sign in, managing keys and performing cryptographic operations.
 */
export interface SudoUserClient {
  /**
   * Presents the sign in UI for federated sign in using an external identity provider.
   */
  presentFederatedSignInUI(): void
  /**
   * Processes tokens from federated sign in returned to the specified URL.
   * The tokens are passed to the web app via a redirect URL.
   *
   * @param url callback URL containing the tokens.
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
   * Returns the subject of the user associated with this client.
   * Note: This is an internal method used by other Sudo platform SDKs.
   *
   * @return user subject.
   */
  getSubject(): string | undefined
  /**
   * Signs out the user from all devices.
   */
  globalSignOut(): Promise<void>
  /**
   * Registers this client against the backend with an external authentication provider. The caller must
   * implement AuthenticationProvider protocol to return the appropriate authentication token required
   * to authorize the registration request.
   *
   * @param authenticationProvider authentication provider that provides the authentication token.
   * @param registrationId registration ID to uniquely identify this registration request.
   * @return user ID of the newly created user
   */
  registerWithAuthenticationProvider(
    authenticationProvider: AuthenticationProvider,
    registrationId?: string,
  ): Promise<string>
  /**
   * Indicates whether or not this client is registered with Sudo Platform backend.
   *
   * @return *true* if the client is registered.
   */
  isRegistered(): Promise<boolean>
  /**
   * Sign into the backend using a private key. The client must have created a private/public key pair via
   * the *registerWithAuthenticationProvider* method.
   *
   * @return Successful authentication result AuthenticationTokens
   */
  signInWithKey(): Promise<AuthenticationTokens>
  /**
   * Clears cached authentication tokens.
   */
  clearAuthenticationTokens(): void
  /**
   * Presents the Cognito hosted UI signout endpoint.
   * When the endpoint is invoked, the hosted web app's cookies
   * will be invalidated, but the user is not logged out of Cognito.
   */
  presentSignOutUI(): void
}

export class DefaultSudoUserClient implements SudoUserClient {
  private config: Config
  private keyManager: KeyManager
  private authenticationStore: AuthenticationStore
  private authUI: AuthUI
  private apiClient: ApiClient
  constructor(
    keyManager?: KeyManager,
    authUI?: AuthUI,
    apiClient?: ApiClient,
    private launchUriFn?: (url: string) => void,
    config?: Config,
  ) {
    this.config =
      config ??
      DefaultConfigurationManager.getInstance().bindConfigSet<Config>(
        Config,
        undefined,
      )

    this.authenticationStore = new AuthenticationStore()

    this.keyManager = keyManager ?? new KeyManager()

    this.authUI =
      authUI ??
      new CognitoAuthUI(
        this.authenticationStore,
        this.keyManager,
        this.config,
        this.launchUriFn,
      )

    this.apiClient =
      apiClient ??
      new ApiClient(
        this.config.identityService.region,
        this.config.identityService.apiUrl,
        this.authUI,
      )
  }

  public presentFederatedSignInUI(): void {
    try {
      this.authUI.presentFederatedSignInUI()
    } catch (error) {
      console.log('Failed to launch the federated sign in UI: ', error)
      throw new AuthenticationError(error)
    }
  }

  public async processFederatedSignInTokens(
    url: string,
  ): Promise<AuthenticationTokens> {
    try {
      const authTokens = await this.authUI.processFederatedSignInTokens(url)
      if (authTokens) {
        return authTokens
      } else {
        throw new AuthenticationError('Authentication tokens missing.')
      }
    } catch (error) {
      console.log('Failed to process the federated sign in redirect: ', error)
      throw new AuthenticationError(error)
    }
  }

  public getIdToken(): string | undefined {
    return this.authUI.getIdToken()
  }

  public getAccessToken(): string | undefined {
    return this.authUI.getAccessToken()
  }

  public getRefreshToken(): string | undefined {
    return this.authUI.getRefreshToken()
  }

  public getTokenExpiry(): Date | undefined {
    return this.authUI.getTokenExpiry()
  }

  public getUserName(): string | undefined {
    return this.authUI.getUserName()
  }

  public getSubject(): string | undefined {
    let sub = undefined
    const idToken = this.getIdToken()
    if (idToken) {
      const decoded: any = JWT.decode(idToken, { complete: true })
      if (decoded) {
        sub = decoded.payload['sub']
      }
    }
    return sub
  }

  public async isSignedIn(): Promise<boolean> {
    return await this.authUI.isSignedIn()
  }

  async refreshTokens(refreshToken: string): Promise<AuthenticationTokens> {
    try {
      const authTokens = await this.authUI.refreshTokens(refreshToken)
      if (authTokens) {
        return authTokens
      } else {
        throw new AuthenticationError('Authentication tokens not found.')
      }
    } catch (error) {
      throw new AuthenticationError(error)
    }
  }

  async getLatestAuthToken(): Promise<string> {
    let idToken = ''
    try {
      idToken = await this.authUI.getLatestAuthToken()
    } catch (err) {
      console.log(err)
    }
    return idToken
  }

  async globalSignOut(): Promise<void> {
    const accessToken = this.getAccessToken()
    if (accessToken) {
      await this.authUI.globalSignOut(accessToken)
      this.clearAuthenticationTokens()
    }
  }

  async registerWithAuthenticationProvider(
    authenticationProvider: AuthenticationProvider,
    registrationId?: string,
  ): Promise<string> {
    console.log('Registering using an external authentication provider')

    if (!(await this.isRegistered())) {
      const authInfo = authenticationProvider.getAuthenticationInfo()
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
        publicKey: JSON.stringify(publicKey),
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

      const userId = await this.authUI.register(uid, validationData)
      if (userId) {
        this.keyManager.addString('userId', userId)
        return userId
      } else {
        throw new RegisterError('Failed to register user.')
      }
    } else {
      throw new RegisterError('Client is already registered')
    }
  }

  async isRegistered(): Promise<boolean> {
    const uid = await this.keyManager.getString('userId')
    const userKeyId = await this.keyManager.getString('userKeyId')

    let privateKey
    let publicKey
    if (userKeyId) {
      const keyPair = await this.keyManager.retrieveKeyPair(userKeyId)
      privateKey = keyPair.privateKey
      publicKey = keyPair.publicKey
    }

    return uid && privateKey && publicKey ? true : false
  }

  async signInWithKey(): Promise<AuthenticationTokens> {
    console.log('Signing in using private key.')
    const uid = await this.keyManager.getString('userId')
    const userKeyId = await this.keyManager.getString('userKeyId')

    if (uid && userKeyId) {
      const authTokens = await this.authUI.signInWithKey(uid, userKeyId)
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
    this.authUI.reset()
  }

  presentSignOutUI(): void {
    this.authUI.presentSignOutUI()
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

  /**
   * Provide a custom auth UI. This is mainly used for unit testing (optional).
   */
  setAuthUI(authUI: AuthUI): void {
    this.authUI = authUI
  }

  /**
   * Provide a custom function to open the sign in url.
   * This is mainly used for unit testing (optional).
   */
  setLaunchUriFn(launchUriFn: (url: string) => void): void {
    this.launchUriFn = launchUriFn
  }
}
