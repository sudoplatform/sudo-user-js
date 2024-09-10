import { AuthUI, CognitoAuthUI } from '../../src/user/auth'
import { IdentityProvider } from '../../src/user/identity-provider'
import { DefaultSudoUserClient } from '../../src/user/user-client'
import { Config } from '../../src/core/sdk-config'
import { AuthenticationStore } from '../../src/core/auth-store'
import {
  mock,
  instance,
  when,
  reset,
  anyString,
  anything,
  verify,
} from 'ts-mockito'
import { generateKeyPairSync } from 'crypto'
import { apiKeyNames } from '../../src/core/api-key-names'
import {
  AuthenticationError,
  DefaultConfigurationManager,
  DefaultLogger,
  NotSignedInError,
  SudoKeyManager,
} from '@sudoplatform/sudo-common'
import { generateKeyPair } from 'crypto'
import { promisify } from 'util'
import { LocalAuthenticationProvider } from '../../src/user/auth-provider'
import { ApiClient } from '../../src/client/apiClient'
import { KeyManager } from '../../src/core/key-manager'
import { userKeyNames } from '../../src/user/user-key-names'
import * as jws from 'jws'

const generateKeyPairAsync = promisify(generateKeyPair)

const globalAny: any = global
globalAny.WebSocket = require('ws')
require('isomorphic-fetch')

const testConfig = {
  federatedSignIn: {
    appClientId: '120q904mra9d5l4psmvdbrgm49',
    signInRedirectUri: 'http://localhost:3000/callback',
    signOutRedirectUri: 'http://localhost:3000/',
    webDomain: 'id-dev-fsso-sudoplatform.auth.us-east-1.amazoncognito.com',
  },
  identityService: {
    region: 'us-east-1',
    poolId: 'us-east-1_ZiPDToF73',
    clientId: '120q904mra9d5l4psmvdbrgm49',
    identityPoolId: 'us-east-1:8fe6d8ed-cd77-4622-b1bb-3f0c147638ad',
    apiUrl:
      'https://mqn7cjrzcrd75jpsma3xw4744a.appsync-api.us-east-1.amazonaws.com/graphql',
    apiKey: 'da2-xejsa343urfifmzkycmz3rqdom',
    bucket: 'ids-userdata-id-dev-fsso-userdatabucket2d841c35-j9x47k5042fk',
    transientBucket:
      'ids-userdata-id-dev-fsso-transientuserdatabucket0-1enoeyoho1sjl',
    registrationMethods: ['TEST', 'FSSO'],
  },
}

const privateKey = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    format: 'pem',
    type: 'pkcs1',
  },
  privateKeyEncoding: {
    format: 'pem',
    type: 'pkcs1',
  },
}).privateKey

const kid = 'test'

const mockIdToken =
  'eyJraWQiOiJ3YzlaekU1eDJMT1BvZVV1XC9cL1JPWnZCV3ozbU1Zem15bXJDTFhYTmRvcms9IiwiYWxnIjoiUlMyNTYifQ.eyJjdXN0b206b2dfaWRlbnRpdHlJZCI6InVzLWVhc3QtMTo4MzE3MThmNC00MzFlLTQ0MDgtYjM0Yi02YmM3MWZjNDJmZmIiLCJzdWIiOiIxMzA4MGI0OS1jMjc3LTQ4M2QtOGQ0Zi0yZGVmZGIyNjE0ZDQiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9aaVBEVG9GNzMiLCJjb2duaXRvOnVzZXJuYW1lIjoiU3Vkb1VzZXItMGNhZmYzNzEtMjc4Zi00ODE0LWE4NjQtN2NhMTdmYWU2ODg1IiwiY3VzdG9tOnVzZXJUeXBlIjoiVEVTVCIsImF1ZCI6IjEyMHE5MDRtcmE5ZDVsNHBzbXZkYnJnbTQ5IiwiY3VzdG9tOmVudGl0bGVtZW50c1NldCI6ImR1bW15X2VudGl0bGVtZW50c19zZXQiLCJldmVudF9pZCI6Ijg2YzFhZDFkLTMwNDItNDFjMC05OTVmLTQ3ZTM0NWNjMjUxZCIsImN1c3RvbTpvZ19zdWIiOiIxMzA4MGI0OS1jMjc3LTQ4M2QtOGQ0Zi0yZGVmZGIyNjE0ZDQiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyMjQyNzA5NywiY3VzdG9tOmlkZW50aXR5SWQiOiJ1cy1lYXN0LTE6ODMxNzE4ZjQtNDMxZS00NDA4LWIzNGItNmJjNzFmYzQyZmZiIiwiZXhwIjoxNjIyNDMwNzAyLCJpYXQiOjE2MjI0MjcxMDJ9.WfhwPvhZn9STh4BSMI_w9PIx9YmAKqEyCJYuJ8NDJCfbATtwSt3QRyYILMjx6mY8IYgnEwyfoDu3Lz5-fb2tBCANz4lykW5lzS7-FxCZ2Ba4Ywr89b2cCayp3Aw3dVSHwwPtFu7-odwnHR9tpZd7jHeIVBlKQIn0WLppRTU9H1AIJh8Pq9FS6YK7uIFaOmNZxe_S18HlT8GQJNwqPZk4P8QEVyazKN9fKidO8EcQVrJoCZnJHCPP9hzum7yo2HJWvWhhlN2Si-VnqfCwDG4hpig9NcCUkGbrOYKCpDjCRZhBhcnpec310X8Lf3Qya8wZEFs1IcYHnhdKpfX4A1DYLQ'

function customLaunchUriFunction(url: string): void {
  location.replace(url)
}

function toArrayBuffer(value: string): ArrayBuffer {
  return new TextEncoder().encode(value).buffer
}

const authUIMock: AuthUI = mock()
const authUI = instance(authUIMock)
const identityProviderMock: IdentityProvider = mock()
const identityProvider = instance(identityProviderMock)
const authenticationStoreMock: AuthenticationStore = mock()
const authenticationStore = instance(authenticationStoreMock)
const keyManagerMock: KeyManager = mock()
const keyManager = instance(keyManagerMock)
const sudoKeyManagerMock: SudoKeyManager = mock()
const sudoKeyManager = instance(sudoKeyManagerMock)
const apiClientMock: ApiClient = mock()
const apiClient = instance(apiClientMock)
DefaultConfigurationManager.getInstance().setConfig(JSON.stringify(testConfig))
const userClient = new DefaultSudoUserClient({
  authenticationStore,
  apiClient,
  authUI,
  identityProvider,
  sudoKeyManager,
})

const config = DefaultConfigurationManager.getInstance().bindConfigSet<Config>(
  Config,
  undefined,
)
const logger = new DefaultLogger()

afterEach((): void => {
  reset(authUIMock)
  reset(authenticationStoreMock)
  reset(keyManagerMock)
  reset(sudoKeyManagerMock)
  reset(identityProviderMock)
  userClient.setAuthUI(authUI)
  userClient.setIdentityProvider(identityProvider)
})

describe('SudoUserClient', () => {
  describe('presentFederatedSignInUI()', () => {
    it('should fail with authentication error - default launchUri - attempt to launch UI with window.open', async () => {
      if (!config.federatedSignIn) {
        fail('federatedSignIn unexpectedly falsy')
      }

      const authUI = new CognitoAuthUI(
        authenticationStore,
        config.federatedSignIn,
        keyManager,
        logger,
      )
      userClient.setAuthUI(authUI)

      expect(() => userClient.presentFederatedSignInUI()).toThrowError(
        AuthenticationError,
      )
    })

    it('should fail with authentication error - custom launchUri - attempt to launch UI with location.replace(url)', async () => {
      if (!config.federatedSignIn) {
        fail('federatedSignIn unexpectedly falsy')
      }

      const authUI = new CognitoAuthUI(
        authenticationStore,
        config.federatedSignIn,
        keyManager,
        logger,
        customLaunchUriFunction,
      )
      userClient.setAuthUI(authUI)

      expect(() => userClient.presentFederatedSignInUI()).toThrowError(
        AuthenticationError,
      )
    })
  })

  describe('processFederatedSignInTokens()', () => {
    it('should complete successfully', async () => {
      when(authUIMock.processFederatedSignInTokens('dummy_url')).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
        refreshToken: 'dummy_refresh_token',
        tokenExpiry: 12345,
      })
      when(sudoKeyManagerMock.getPassword(userKeyNames.userId)).thenResolve(
        toArrayBuffer('dummy_username'),
      )
      when(
        identityProviderMock.refreshTokens('dummy_refresh_token'),
      ).thenResolve({
        idToken: mockIdToken,
        accessToken: 'dummy_access_token',
        refreshToken: 'dummy_refresh_token',
        tokenExpiry: 12345,
      })

      const authTokens =
        await userClient.processFederatedSignInTokens('dummy_url')

      expect(authTokens.idToken).toBe(mockIdToken)
      expect(authTokens.accessToken).toBe('dummy_access_token')
      expect(authTokens.refreshToken).toBe('dummy_refresh_token')
      expect(authTokens.tokenExpiry).toBe(12345)
    })

    it('should fail with authentication error', async () => {
      when(authUIMock.processFederatedSignInTokens('dummy_url')).thenReject()

      await expect(
        userClient.processFederatedSignInTokens('dummy_url'),
      ).rejects.toThrowError(AuthenticationError)
    })
  })

  describe('getSubject()', () => {
    it('should complete successfully', async () => {
      const now = Date.now()
      let signOptions: jws.SignOptions = {
        header: { alg: 'RS256', kid },
        payload: {
          jti: '123',
          aud: 'testAudience',
          exp: now + 10000, // after 10 seconds
          sub: 'dummy_sub',
          iss: 'https://test.sudoplatform.com',
        },
        privateKey: privateKey,
      }

      const token = jws.sign(signOptions)

      when(sudoKeyManagerMock.getPassword(apiKeyNames.idToken)).thenResolve(
        toArrayBuffer(token),
      )
      const sub = await userClient.getSubject()
      expect(sub).toBe('dummy_sub')
    })
  })

  describe('getUserName()', () => {
    it('should complete successfully', async () => {
      when(sudoKeyManagerMock.getPassword(userKeyNames.userId)).thenResolve(
        toArrayBuffer('test_user'),
      )
      const userName = await userClient.getUserName()
      expect(userName).toBe('test_user')
    })
  })

  describe('refreshTokens()', () => {
    it('should complete successfully', async () => {
      when(sudoKeyManagerMock.getPassword(userKeyNames.userId)).thenResolve(
        toArrayBuffer('test_user'),
      )
      when(identityProviderMock.refreshTokens('refresh_token')).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
        refreshToken: 'dummy_refresh_token',
        tokenExpiry: 12345,
      })

      const authTokens = await userClient.refreshTokens('refresh_token')

      expect(authTokens.idToken).toBe('dummy_id_token')
      expect(authTokens.accessToken).toBe('dummy_access_token')
      expect(authTokens.refreshToken).toBe('dummy_refresh_token')
      expect(authTokens.tokenExpiry).toBe(12345)
    })

    it('should fail with authentication error', async () => {
      when(sudoKeyManagerMock.getPassword(userKeyNames.userId)).thenResolve(
        toArrayBuffer('test_user'),
      )
      when(identityProviderMock.refreshTokens('refresh_token')).thenReject()

      await expect(
        userClient.refreshTokens('refresh_token'),
      ).rejects.toThrowError(AuthenticationError)
    })
  })

  describe('getLatestAuthToken()', () => {
    it('should complete successfully', async () => {
      const tokenExpiry = new Date().getTime() + 3600000
      const validTokenExpiry = tokenExpiry / 1000

      when(sudoKeyManagerMock.getPassword(apiKeyNames.idToken)).thenResolve(
        toArrayBuffer('dummy_id_token'),
      )

      when(
        sudoKeyManagerMock.getPassword(apiKeyNames.refreshToken),
      ).thenResolve(toArrayBuffer('dummy_refresh_token'))
      when(sudoKeyManagerMock.getPassword(apiKeyNames.tokenExpiry)).thenResolve(
        toArrayBuffer(validTokenExpiry.toString()),
      )

      const idToken = await userClient.getLatestAuthToken()
      expect(idToken).toBe('dummy_id_token')
    })

    it('should return empty token - user not signed in', async () => {
      when(sudoKeyManagerMock.getPassword(apiKeyNames.idToken)).thenResolve()
      when(
        sudoKeyManagerMock.getPassword(apiKeyNames.refreshToken),
      ).thenResolve()
      when(
        sudoKeyManagerMock.getPassword(apiKeyNames.tokenExpiry),
      ).thenResolve()

      const empty = ''
      const idToken = await userClient.getLatestAuthToken()
      expect(idToken).toBe(empty)
    })

    it('should return empty token - error encountered calling refreshTokens', async () => {
      when(sudoKeyManagerMock.getPassword(apiKeyNames.idToken)).thenResolve(
        toArrayBuffer('id_token'),
      )
      when(
        sudoKeyManagerMock.getPassword(apiKeyNames.refreshToken),
      ).thenResolve(toArrayBuffer('refresh_token'))
      when(sudoKeyManagerMock.getPassword(apiKeyNames.tokenExpiry)).thenResolve(
        toArrayBuffer('100'),
      )
      when(identityProviderMock.refreshTokens('refresh_token')).thenReject()

      const empty = ''
      const idToken = await userClient.getLatestAuthToken()
      expect(idToken).toBe(empty)
    })
  })

  describe('signOut()', () => {
    it('should complete successfully', async () => {
      let isSignedOut = false
      when(
        sudoKeyManagerMock.getPassword(apiKeyNames.refreshToken),
      ).thenResolve(toArrayBuffer('dummy_refresh_token'))
      await userClient.signOut()
      isSignedOut = true
      expect(isSignedOut).toBeTruthy()
    })

    it('should fail if not signed in', async () => {
      await expect(userClient.signOut()).rejects.toThrowError(NotSignedInError)
    })
  })

  describe('globalSignOut()', () => {
    it('should complete successfully', async () => {
      let isSignedOut = false
      when(sudoKeyManagerMock.getPassword(apiKeyNames.idToken)).thenResolve(
        toArrayBuffer('dummy_id_token'),
      )
      when(sudoKeyManagerMock.getPassword(apiKeyNames.accessToken)).thenResolve(
        toArrayBuffer('dummy_access_token'),
      )
      when(
        sudoKeyManagerMock.getPassword(apiKeyNames.refreshToken),
      ).thenResolve(toArrayBuffer('dummy_refresh_token'))
      when(sudoKeyManagerMock.getPassword(apiKeyNames.tokenExpiry)).thenResolve(
        toArrayBuffer(Number(new Date().getTime() + 60 * 1000).toString()),
      )
      when(
        sudoKeyManagerMock.getPassword(apiKeyNames.refreshTokenExpiry),
      ).thenResolve(
        toArrayBuffer(
          Number(new Date().getTime() + 60 * 60 * 1000 + 10000).toString(),
        ),
      )
      await userClient.globalSignOut()
      isSignedOut = true
      expect(isSignedOut).toBeTruthy()
    })

    it('should fail if not signed in', async () => {
      await expect(userClient.globalSignOut()).rejects.toThrowError(
        NotSignedInError,
      )
    })
  })

  describe('presentSignOutUI()', () => {
    it('should fail trying to invoke signout url - attempt to launch UI with window.open', async () => {
      if (!config.federatedSignIn) {
        fail('federatedSignIn unexpectedly falsy')
      }

      const authUI = new CognitoAuthUI(
        authenticationStore,
        config.federatedSignIn,
        keyManager,
        logger,
      )
      userClient.setAuthUI(authUI)

      expect(() => userClient.presentSignOutUI()).toThrowError(
        new Error('window is not defined'),
      )
    })
  })

  describe('isSignedIn()', () => {
    it('should complete successfully', async () => {
      when(sudoKeyManagerMock.getPassword(apiKeyNames.idToken)).thenResolve(
        toArrayBuffer('dummy_id_token'),
      )
      when(sudoKeyManagerMock.getPassword(apiKeyNames.accessToken)).thenResolve(
        toArrayBuffer('dummy_access_token'),
      )
      when(
        sudoKeyManagerMock.getPassword(apiKeyNames.refreshToken),
      ).thenResolve(toArrayBuffer('dummy_refresh_token'))
      when(sudoKeyManagerMock.getPassword(apiKeyNames.tokenExpiry)).thenResolve(
        toArrayBuffer(Number(new Date().getTime() + 60 * 1000).toString()),
      )
      when(
        sudoKeyManagerMock.getPassword(apiKeyNames.refreshTokenExpiry),
      ).thenResolve(
        toArrayBuffer(
          Number(new Date().getTime() + 60 * 60 * 1000 + 10000).toString(),
        ),
      )
      expect(await userClient.isSignedIn()).toBeTruthy()
    })
  })

  describe('customFSSO()', () => {
    it('should complete successfully', async () => {
      const keyPair = await generateKeyPairAsync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          format: 'pem',
          type: 'pkcs1',
        },
        privateKeyEncoding: {
          format: 'pem',
          type: 'pkcs1',
        },
      })

      const authenticationProvider = new LocalAuthenticationProvider(
        'client_system_test_iss',
        keyPair.privateKey,
        'dummy_key_id',
        'dummy_username',
      )

      const authInfo = await authenticationProvider.getAuthenticationInfo()
      expect(authInfo.isValid()).toBeTruthy()
      expect(authInfo.getUsername()).toBe('dummy_username')

      const token = authInfo.encode()

      const decoded: any = jws.decode(token)
      expect(decoded.header['kid']).toBe('dummy_key_id')

      const verified: any = jws.verify(token, 'RS256', keyPair.publicKey)
      expect(verified).toBeTruthy()

      const authUIMock: CognitoAuthUI = mock()
      const authUI = instance(authUIMock)
      userClient.setAuthUI(authUI)

      when(
        identityProviderMock.signInWithToken(
          'dummy_username',
          anyString(),
          'FSSO',
        ),
      ).thenResolve({
        idToken: mockIdToken,
        accessToken: 'dummy_access_token',
        refreshToken: 'dummy_refresh_token',
        tokenExpiry: 1,
      })

      when(keyManagerMock.getString(apiKeyNames.idToken)).thenResolve(
        mockIdToken,
      )
      when(sudoKeyManagerMock.getPassword(apiKeyNames.idToken)).thenResolve(
        toArrayBuffer(mockIdToken),
      )

      const tokens = await userClient.signInWithAuthenticationProvider(
        authenticationProvider,
      )

      expect(tokens.idToken).toBe(mockIdToken)
      expect(tokens.accessToken).toBe('dummy_access_token')
      expect(tokens.refreshToken).toBe('dummy_refresh_token')
      expect(tokens.tokenExpiry).toBe(1)
      expect(await userClient.getUserClaim('custom:identityId')).toBeTruthy()
    })
  })

  describe('disabledUser()', () => {
    it('signInWithToken should fail due to user being disabled', async () => {
      const keyPair = await generateKeyPairAsync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          format: 'pem',
          type: 'pkcs1',
        },
        privateKeyEncoding: {
          format: 'pem',
          type: 'pkcs1',
        },
      })

      const authenticationProvider = new LocalAuthenticationProvider(
        'client_system_test_iss',
        keyPair.privateKey,
        'dummy_key_id',
        'disabled_username',
      )

      const authInfo = await authenticationProvider.getAuthenticationInfo()
      expect(authInfo.isValid()).toBeTruthy()
      expect(authInfo.getUsername()).toBe('disabled_username')

      when(
        identityProviderMock.signInWithToken(
          'disabled_username',
          anyString(),
          anyString(),
        ),
      ).thenReject(new AuthenticationError('User disabled')) // reject due to user disabled error being returned from Cognito

      await expect(
        userClient.signInWithAuthenticationProvider(authenticationProvider),
      ).rejects.toThrowError(AuthenticationError)
    })
  })

  describe('resetUserData()', () => {
    it('throws NotSignedInError if no username', async () => {
      when(keyManagerMock.getString(anything())).thenResolve(undefined)
      await expect(userClient.resetUserData()).rejects.toThrow(NotSignedInError)
    })

    it('succeeds when signed in and adminAPiClient.restUser succeeds', async () => {
      // has to be > 1 hr in the future, so use 2 hours
      const expireInFuture = new Date().getTime() + 120 * 60 * 1000
      when(sudoKeyManagerMock.getPassword(anything()))
        .thenResolve(new TextEncoder().encode('dummy-idToken'))
        .thenResolve(new TextEncoder().encode('dummy-accessToken'))
        .thenResolve(new TextEncoder().encode('dummy-refreshToken'))
        .thenResolve(new TextEncoder().encode(expireInFuture.toString()))
        .thenResolve(new TextEncoder().encode(expireInFuture.toString()))
      when(apiClientMock.reset()).thenResolve(undefined)

      await expect(userClient.resetUserData()).resolves.toBe(undefined)
    })
  })
})
