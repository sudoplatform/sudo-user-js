import { SudoKeyManager } from '@sudoplatform/sudo-common'
import { AuthenticationProvider } from './auth-provider'

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
  getIdToken(): Promise<string | undefined>
  /**
   * Returns the access token cached from the last sign-in.
   *
   * @return access token.
   */
  getAccessToken(): Promise<string | undefined>
  /**
   * Returns the refresh token cached from the last sign-in.
   *
   * @return refresh token.
   */
  getRefreshToken(): Promise<string | undefined>
  /**
   * Returns the ID and access token expiry cached from the last sign-in.
   *
   * @return token expiry.
   */
  getTokenExpiry(): Promise<Date | undefined>
  /**
   * Returns the refresh token expiry cached from the last sign-in.
   *
   * @return refresh token expiry.
   */
  getRefreshTokenExpiry(): Promise<Date | undefined>
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
  getUserName(): Promise<string | undefined>
  /**
   * Sets the user name associated with this client.
   *
   * @param name user name.
   */
  setUserName(name: string): Promise<void>
  /**
   * Returns the subject of the user associated with this client.
   * Note: This is an internal method used by other Sudo platform SDKs.
   *
   * @return user subject.
   */
  getSubject(): Promise<string | undefined>
  /**
   * Returns the specified claim associated with the user's identity.
   *
   * @param name claim name.
   */
  getUserClaim(name: string): Promise<any | undefined>
  /**
   * Signs out the user from this device.
   */
  signOut(): Promise<void>
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
   * Sign into the backend using an external authentication provider. Caller must implement
   * *AuthenticationProvider* interface to return the appropriate authentication token associated with
   * the external identity registered with *registerWithAuthenticationProvider*.
   *
   * @param authenticationProvider authentication provider that provides the authentication token.
   * @return authentication tokens associated with the successful sign in.
   */
  signInWithAuthenticationProvider(
    authenticationProvider: AuthenticationProvider,
  ): Promise<AuthenticationTokens>
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
   * @return authentication tokens associated with the successful sign in.
   */
  signInWithKey(): Promise<AuthenticationTokens>
  /**
   * Clears cached authentication tokens.
   */
  clearAuthenticationTokens(): Promise<void>
  /**
   * Presents the Cognito hosted UI signout endpoint.
   * When the endpoint is invoked, the hosted web app's cookies
   * will be invalidated, but the user is not logged out of Cognito.
   */
  presentSignOutUI(): void
  /**
   * Resets internal state and clears any cached data.
   */
  reset(): void

  /**
   * Getter to retrieve the SudoKeyManager
   */
  readonly sudoKeyManager: SudoKeyManager
}
