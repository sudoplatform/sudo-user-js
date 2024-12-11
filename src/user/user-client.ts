/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  AuthenticationError,
  DefaultLogger,
  DefaultSudoKeyManager,
  FatalError,
  KeyNotFoundError,
  Logger,
  NotAuthorizedError,
  NotRegisteredError,
  NotSignedInError,
  PublicKeyFormat,
  RegisterError,
  SudoKeyManager,
} from '@sudoplatform/sudo-common'
import { WebSudoCryptoProvider } from '@sudoplatform/sudo-web-crypto-provider'
import { v4 } from 'uuid'
import { AuthenticationProvider } from '..'
import { ApiClient } from '../client/apiClient'
import { apiKeyNames } from '../core/api-key-names'
import { AuthenticationStore } from '../core/auth-store'
import { DefaultKeyManager, PublicKey } from '../core/key-manager'
import { Config, getIdentityServiceConfig } from '../core/sdk-config'
import { AuthUI, CognitoAuthUI } from './auth'
import { AlreadyRegisteredError } from './error'
import {
  CognitoUserPoolIdentityProvider,
  IdentityProvider,
} from './identity-provider'
import { AuthenticationTokens, SudoUserClient } from './user-client-interface'
import { userKeyNames } from './user-key-names'
import * as jws from 'jws'
import { parseToken } from '../utils/parse-token'

export interface SudoUserOptions {
  authenticationStore?: AuthenticationStore
  sudoKeyManager?: SudoKeyManager
  apiClient?: ApiClient
  authUI?: AuthUI
  identityProvider?: IdentityProvider
  launchUriFn?: (url: string) => void
  config?: Config
  logger?: Logger
}

export class DefaultSudoUserClient implements SudoUserClient {
  private config: Config
  private keyManager: DefaultKeyManager
  private sudoUserKeyManager: SudoKeyManager
  private authenticationStore: AuthenticationStore
  private identityProvider: IdentityProvider
  private apiClient: ApiClient
  private logger: Logger
  private authUI?: AuthUI
  private launchUriFn?: (url: string) => void

  constructor(options?: SudoUserOptions) {
    this.logger = options?.logger ?? new DefaultLogger('SudoUser', 'warn')

    this.config = options?.config ?? getIdentityServiceConfig()

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
    this.keyManager = new DefaultKeyManager(this.sudoUserKeyManager)

    this.launchUriFn = options?.launchUriFn

    this.identityProvider =
      options?.identityProvider ??
      new CognitoUserPoolIdentityProvider(
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
          this.keyManager,
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
    } catch (err) {
      const error = err as Error
      this.logger.error('Failed to launch the federated sign in UI.', { error })
      throw new AuthenticationError(error.message)
    }
  }

  public async processFederatedSignInTokens(
    url: string,
  ): Promise<AuthenticationTokens> {
    try {
      let authTokens = await this.authUI?.processFederatedSignInTokens(url)
      if (authTokens) {
        authTokens = await this.registerFederatedIdAndRefreshTokens(authTokens)
        return authTokens
      } else {
        throw new AuthenticationError('Authentication tokens missing.')
      }
    } catch (err) {
      const error = err as Error
      this.logger.error('Failed to process the federated sign in redirect.', {
        error,
      })
      throw new AuthenticationError(error.message)
    }
  }

  public async getIdToken(): Promise<string | undefined> {
    return await this.keyManager.getString(apiKeyNames.idToken)
  }

  public async getAccessToken(): Promise<string | undefined> {
    return await this.keyManager.getString(apiKeyNames.accessToken)
  }

  public async getRefreshToken(): Promise<string | undefined> {
    return await this.keyManager.getString(apiKeyNames.refreshToken)
  }

  public async getTokenExpiry(): Promise<Date | undefined> {
    const expiry = await this.keyManager.getString(apiKeyNames.tokenExpiry)
    return expiry ? new Date(Number(expiry) * 1000) : undefined
  }

  public async getRefreshTokenExpiry(): Promise<Date | undefined> {
    let expiry: Date | undefined = undefined
    const timeSinceEpoch = await this.keyManager.getString(
      apiKeyNames.refreshTokenExpiry,
    )
    if (timeSinceEpoch) {
      expiry = new Date(Number(timeSinceEpoch))
    }
    return expiry
  }

  public async getUserName(): Promise<string | undefined> {
    try {
      return await this.keyManager.getString(userKeyNames.userId)
    } catch {
      return undefined
    }
  }

  public async setUserName(name: string): Promise<void> {
    await this.keyManager.removeItem(userKeyNames.userId)
    await this.keyManager.addString(userKeyNames.userId, name)
  }

  public async getUserClaim(name: string): Promise<any | undefined> {
    const idToken = await this.getIdToken()
    if (!idToken) return undefined
    return this.getTokenClaim(idToken, name)
  }

  public async getSubject(): Promise<string | undefined> {
    return await this.getUserClaim('sub')
  }

  public async isSignedIn(): Promise<boolean> {
    try {
      const authTokens = await this.getAuthTokens()
      const expiry = await this.getRefreshTokenExpiry()
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
        return false
      }
    } catch {
      // The key manager throws a KeyNotFoundError if an item is not found
      // in which case we want to indicate that the user is not signed in.
      return false
    }
  }

  public async refreshTokens(
    refreshToken: string,
  ): Promise<AuthenticationTokens> {
    try {
      const uid = await this.getUserName()
      if (uid) {
        const authTokens =
          await this.identityProvider.refreshTokens(refreshToken)
        await this.storeTokens(uid, authTokens)
        return authTokens
      } else {
        throw new NotRegisteredError('Not registered.')
      }
    } catch (err) {
      const error = err as Error
      throw new AuthenticationError(error.message)
    }
  }

  public async getLatestAuthToken(): Promise<string> {
    try {
      const idToken = await this.getIdToken()
      const refreshToken = await this.getRefreshToken()
      const expiry = await this.getTokenExpiry()

      if (idToken && refreshToken && expiry) {
        if (expiry.getTime() > new Date().getTime() + 600 * 1000) {
          return idToken
        } else {
          try {
            const authTokens = await this.refreshTokens(refreshToken)
            return authTokens.idToken
          } catch (error) {
            this.logger.info('getLatestAuthToken: Token refresh failed', {
              error,
            })
            // return an empty id token
            return ''
          }
        }
      } else {
        // If tokens are missing then it's likely due to the client not being signed in.
        // Return an empty id token.
        return ''
      }
    } catch {
      // The key manager throws a KeyNotFoundError if an item is not found
      // which would indicate that the client is likely not signed in.
      // Return an empty id token.
      return ''
    }
  }

  public async signOut(): Promise<void> {
    let refreshToken: string | undefined
    try {
      refreshToken = await this.getRefreshToken()
    } catch (err) {
      if (err instanceof KeyNotFoundError) {
        throw new NotSignedInError()
      } else {
        throw err
      }
    }
    if (refreshToken) {
      await this.identityProvider.signOut(refreshToken)
    } else {
      throw new NotSignedInError()
    }
  }

  public async globalSignOut(): Promise<void> {
    if (!(await this.isSignedIn())) {
      throw new NotSignedInError()
    }
    await this.apiClient.globalSignOut()
    await this.clearAuthenticationTokens()
  }

  public async registerWithAuthenticationProvider(
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
      const uid = authInfo.getUsername()

      const publicKey = await this.generateRegistrationData()

      const data = {
        challengeType: authInfo.type,
        answer: token,
        registrationId: registrationId ? registrationId : v4(),
        publicKey: JSON.stringify(publicKeyToRSAPublicKey(publicKey)),
      }

      const validationData = Object.keys(data).map(
        (
          key,
        ): {
          Name: string
          Value: string
        } => {
          return {
            Name: key,
            Value: (data as any)[key],
          }
        },
      )

      const userId = await this.identityProvider.register(uid, validationData)
      if (userId) {
        await this.setUserName(userId)
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

  public async signInWithAuthenticationProvider(
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

    let authTokens = await this.identityProvider.signInWithToken(
      uid,
      token,
      type,
    )
    await this.storeTokens(uid, authTokens)
    authTokens = await this.registerFederatedIdAndRefreshTokens(authTokens)
    return authTokens
  }

  public async isRegistered(): Promise<boolean> {
    try {
      const uid = await this.getUserName()
      return uid ? true : false
    } catch {
      return false
    }
  }

  public async signInWithKey(): Promise<AuthenticationTokens> {
    this.logger.info('Signing in using private key.')
    const uid = await this.getUserName()
    const userKeyId = await this.keyManager.getString('userKeyId')

    if (uid && userKeyId) {
      let authTokens = await this.identityProvider.signInWithKey(uid, userKeyId)
      if (authTokens) {
        await this.storeTokens(uid, authTokens)
        authTokens = await this.registerFederatedIdAndRefreshTokens(authTokens)
        return authTokens
      } else {
        throw new FatalError('Unexpected error. Unable to sign in.')
      }
    } else {
      throw new NotRegisteredError('Not registered.')
    }
  }

  public async deregister(): Promise<void> {
    await this.apiClient.deregister()
    await this.keyManager.reset()
    await this.clearAuthenticationTokens()
  }

  public async clearAuthenticationTokens(): Promise<void> {
    await this.keyManager.removeItem(apiKeyNames.idToken)
    await this.keyManager.removeItem(apiKeyNames.accessToken)
    await this.keyManager.removeItem(apiKeyNames.refreshToken)
    await this.keyManager.removeItem(apiKeyNames.tokenExpiry)

    this.authenticationStore.reset()

    if (this.authUI) {
      this.authUI.reset()
    }
  }

  public presentSignOutUI(): void {
    this.authUI?.presentSignOutUI()
  }

  public async reset(): Promise<void> {
    await this.keyManager.reset()
    await this.apiClient.reset()
    await this.clearAuthenticationTokens()
  }

  public async resetUserData(): Promise<void> {
    if (await this.isSignedIn()) {
      await this.apiClient?.resetUserData()
    } else {
      throw new NotSignedInError()
    }
  }

  private getTokenClaim(token: string, name: string): string | undefined {
    let claim = undefined
    const decoded: any = jws.decode(token)
    if (decoded && decoded.payload) {
      const payload = parseToken(decoded.payload)
      claim = payload[name]
    }
    return claim
  }

  /**
   * Store the authentication tokens and user id of the signed in user. This function
   * is only called when a user has successfully signed in using a private key.
   */
  private async storeTokens(
    uid: string,
    authTokens: AuthenticationTokens,
  ): Promise<void> {
    await this.keyManager.removeItem(userKeyNames.userId)
    await this.keyManager.removeItem(apiKeyNames.idToken)
    await this.keyManager.removeItem(apiKeyNames.accessToken)
    await this.keyManager.removeItem(apiKeyNames.refreshToken)
    await this.keyManager.removeItem(apiKeyNames.tokenExpiry)

    await this.keyManager.addString(userKeyNames.userId, uid)
    await this.keyManager.addString(apiKeyNames.idToken, authTokens.idToken)
    await this.keyManager.addString(
      apiKeyNames.accessToken,
      authTokens.accessToken,
    )
    await this.keyManager.addString(
      apiKeyNames.refreshToken,
      authTokens.refreshToken,
    )

    const decoded: any = jws.decode(authTokens.idToken)

    if (decoded && decoded.payload) {
      const payload = parseToken(decoded.payload)
      const tokenExpiry = payload['exp']
      await this.keyManager.addString(apiKeyNames.tokenExpiry, tokenExpiry)
    }
  }

  private async registerFederatedIdAndRefreshTokens(
    authTokens: AuthenticationTokens,
  ): Promise<AuthenticationTokens> {
    const identityId = this.getTokenClaim(
      authTokens.idToken,
      'custom:identityId',
    )

    if (identityId) {
      return authTokens
    } else {
      await this.apiClient.registerFederatedId({
        idToken: authTokens.idToken,
      })
      // Refresh the ID token so the identity ID is present as a claim.
      const newAuthTokens = await this.refreshTokens(authTokens.refreshToken)
      return newAuthTokens
    }
  }

  private async generateRegistrationData(): Promise<PublicKey> {
    const keyId = await this.keyManager.generateKeyPair()
    await this.keyManager.removeItem(userKeyNames.userKeyId)
    await this.keyManager.addString(userKeyNames.userKeyId, keyId)
    const publicKey = await this.keyManager.exportPublicKey(keyId)
    return publicKey
  }

  private async getAuthTokens(): Promise<AuthenticationTokens | undefined> {
    const idToken = await this.getIdToken()
    const accessToken = await this.getAccessToken()
    const refreshToken = await this.getRefreshToken()
    const tokenExpiry = await this.getTokenExpiry()

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
