import { AuthenticationError, Logger } from '@sudoplatform/sudo-common'
import { CognitoAuth } from 'amazon-cognito-auth-js'
import { apiKeyNames } from '../core/api-key-names'
import { AuthenticationStore } from '../core/auth-store'
import { FederatedSignInConfig } from '../core/sdk-config'
import { Subscriber } from '../core/subscriber'
import {
  createResolvablePromise,
  ResolvablePromise,
} from '../utils/resolvable-promise'
import { AuthenticationTokens } from './user-client-interface'

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
   * Refresh the access and ID tokens using the refresh token.
   *
   * @param refreshToken refresh token used to refresh the access and ID tokens.
   * @return Successful authentication result AuthenticationTokens containing refreshed tokens
   */
  refreshTokens(refreshToken: string): Promise<AuthenticationTokens>
  /**
   * Resets any internal state.
   */
  reset(): void
  /**
   * Presents the Cognito hosted UI signout endpoint.
   * When the endpoint is invoked, the hosted web app's cookies
   * will be invalidated, but the user is not logged out of Cognito.
   */
  presentSignOutUI(): void
}

export class CognitoAuthUI implements AuthUI, Subscriber {
  private auth: CognitoAuth
  private tokensRefreshedPromise?: ResolvablePromise<AuthenticationTokens>
  private refreshTokenLifetime: number
  private logger: Logger

  constructor(
    private authenticationStore: AuthenticationStore,
    private federatedSignInConfig: FederatedSignInConfig,
    logger: Logger,
    private launchUriFn?: (url: string) => void,
  ) {
    this.authenticationStore.subscribe(this)
    this.auth = this.initCognitoAuthSDK()

    const refreshTokenLifetime = this.federatedSignInConfig.refreshTokenLifetime
    this.refreshTokenLifetime = refreshTokenLifetime ?? 60
    this.logger = logger
  }

  private initCognitoAuthSDK(): CognitoAuth {
    const cognitoAuthConfig = {
      ClientId: this.federatedSignInConfig.appClientId,
      AppWebDomain: this.federatedSignInConfig.webDomain,
      IdentityProvider: this.federatedSignInConfig.identityProvider,
      RedirectUriSignIn: this.federatedSignInConfig.signInRedirectUri,
      RedirectUriSignOut: this.federatedSignInConfig.signOutRedirectUri,
      TokenScopesArray: ['openid', 'aws.cognito.signin.user.admin'],
      Storage: this.authenticationStore,
      LaunchUri: this.launchUriFn,
    }

    const auth = new CognitoAuth(cognitoAuthConfig)
    auth.useCodeGrantFlow()

    auth.userhandler = {
      onSuccess: (result) => {
        this.logger.info('Successfully signed in.', { result })
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
    this.tokensRefreshedPromise = createResolvablePromise<AuthenticationTokens>()
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
    this.logger.debug('Updated: ', { itemName })
  }

  async refreshTokens(refreshToken: string): Promise<AuthenticationTokens> {
    this.tokensRefreshedPromise = createResolvablePromise<AuthenticationTokens>()
    this.auth.refreshSession(refreshToken)
    const authTokens = await this.tokensRefreshedPromise
    return authTokens
  }

  reset(): void {
    this.authenticationStore.reset()
    const cognitoAuthAny = this.auth as any
    cognitoAuthAny.clearCachedTokensScopes()
    cognitoAuthAny.signInUserSession = null
    cognitoAuthAny.signInUserSession = cognitoAuthAny.getCachedSession()
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

  private getAuthTokens(): AuthenticationTokens | undefined {
    const idToken = this.authenticationStore.getItem(apiKeyNames.idToken)
    const accessToken = this.authenticationStore.getItem(
      apiKeyNames.accessToken,
    )
    const refreshToken = this.authenticationStore.getItem(
      apiKeyNames.refreshToken,
    )
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

  private getTokenExpiry(): Date | undefined {
    const expiry = this.authenticationStore.getItem(apiKeyNames.tokenExpiry)
    return expiry ? new Date(Number(expiry) * 1000) : undefined
  }
}
