import { AuthUI, CognitoAuthUI } from '../../src/user/auth'
import { IdentityProvider } from '../../src/user/identity-provider'
import { DefaultSudoUserClient } from '../../src/user/user-client'
import { Config } from '../../src/core/sdk-config'
import { AuthenticationStore } from '../../src/core/auth-store'
import { mock, instance, when, reset, anyString } from 'ts-mockito'
import * as JWT from 'jsonwebtoken'
import { generateKeyPairSync } from 'crypto'
import { KeyPairKey, PrivateKey } from '../../src/utils/key-pair'
import { apiKeyNames } from '../../src/core/api-key-names'
import {
  DefaultConfigurationManager,
  DefaultLogger,
} from '@sudoplatform/sudo-common'
import { generateKeyPair } from 'crypto'
import { promisify } from 'util'
import { LocalAuthenticationProvider } from '../../src/user/auth-provider'
import { ApiClient } from '../../src/client/apiClient'
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

const testKey: PrivateKey & KeyPairKey = {
  kid: 'test',
  provider: 'provider',
  type: 'type',
  privateKey: generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      format: 'pem',
      type: 'pkcs1',
    },
    privateKeyEncoding: {
      format: 'pem',
      type: 'pkcs1',
    },
  }).privateKey,
}

function customLaunchUriFunction(url: string): void {
  location.replace(url)
}

const authUIMock: AuthUI = mock()
const authUI = instance(authUIMock)
const identityProviderMock: IdentityProvider = mock()
const identityProvider = instance(identityProviderMock)
const authenticationStoreMock: AuthenticationStore = mock()
const authenticationStore = instance(authenticationStoreMock)
const apiClientMock: ApiClient = mock()
const apiClient = instance(apiClientMock)
DefaultConfigurationManager.getInstance().setConfig(JSON.stringify(testConfig))
const userClient = new DefaultSudoUserClient({
  authenticationStore,
  apiClient,
  authUI,
  identityProvider,
})

const config = DefaultConfigurationManager.getInstance().bindConfigSet<Config>(
  Config,
  undefined,
)
const logger = new DefaultLogger()

afterEach((): void => {
  reset(authUIMock)
  reset(authenticationStoreMock)
  reset(identityProviderMock)
  userClient.setAuthUI(authUI)
  userClient.setIdentityProvider(identityProvider)
})

describe('SudoUserClient', () => {
  describe('presentFederatedSignInUI()', () => {
    it('should fail with authentication error - default launchUri - attempt to launch UI with window.open', async () => {
      const authUI = new CognitoAuthUI(
        authenticationStore,
        config.federatedSignIn,
        logger,
      )
      userClient.setAuthUI(authUI)

      try {
        userClient.presentFederatedSignInUI()
        fail('Expected error not thrown.')
      } catch (error) {
        expect(error.name).toMatch('AuthenticationError')
      }
    })

    it('should fail with authentication error - custom launchUri - attempt to launch UI with location.replace(url)', async () => {
      const authUI = new CognitoAuthUI(
        authenticationStore,
        config.federatedSignIn,
        logger,
        customLaunchUriFunction,
      )
      userClient.setAuthUI(authUI)

      try {
        userClient.presentFederatedSignInUI()
        fail('Expected error not thrown.')
      } catch (error) {
        expect(error.name).toMatch('AuthenticationError')
      }
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

      try {
        const authTokens = await userClient.processFederatedSignInTokens(
          'dummy_url',
        )

        expect(authTokens.idToken).toBe('dummy_id_token')
        expect(authTokens.accessToken).toBe('dummy_access_token')
        expect(authTokens.refreshToken).toBe('dummy_refresh_token')
        expect(authTokens.tokenExpiry).toBe(12345)
      } catch (error) {
        fail('Should not have thrown an error')
      }
    })

    it('should fail with authentication error', async () => {
      when(authUIMock.processFederatedSignInTokens('dummy_url')).thenReject()

      try {
        await userClient.processFederatedSignInTokens('dummy_url')
        fail('Expected error not thrown.')
      } catch (error) {
        expect(error.name).toMatch('AuthenticationError')
      }
    })
  })

  describe('getSubject()', () => {
    const token = JWT.sign({}, testKey.privateKey, {
      jwtid: '123',
      audience: 'testAudience',
      expiresIn: '10s',
      notBefore: '0m',
      subject: 'dummy_sub',
      issuer: 'https://test.sudoplatform.com',
      header: { alg: 'RS256', kid: testKey.kid },
      algorithm: 'RS256',
    })

    it('should complete successfully', async () => {
      when(authenticationStoreMock.getItem(apiKeyNames.idToken)).thenReturn(
        token,
      )
      const sub = userClient.getSubject()
      expect(sub).toBe('dummy_sub')
    })
  })

  describe('getUserName()', () => {
    it('should complete successfully', async () => {
      when(authenticationStoreMock.getItem(apiKeyNames.userId)).thenReturn(
        'test_user',
      )

      const userName = userClient.getUserName()
      expect(userName).toBe('test_user')
    })
  })

  describe('refreshTokens()', () => {
    it('should complete successfully', async () => {
      when(authenticationStoreMock.getItem(apiKeyNames.userId)).thenReturn(
        'test_user',
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
      when(authenticationStoreMock.getItem(apiKeyNames.userId)).thenReturn(
        'test_user',
      )
      when(identityProviderMock.refreshTokens('refresh_token')).thenReject()

      try {
        await userClient.refreshTokens('refresh_token')
        fail('Expected error not thrown.')
      } catch (error) {
        expect(error.name).toMatch('AuthenticationError')
      }
    })
  })

  describe('getLatestAuthToken()', () => {
    it('should complete successfully', async () => {
      const authUI = new CognitoAuthUI(
        authenticationStore,
        config.federatedSignIn,
        logger,
      )
      userClient.setAuthUI(authUI)

      const tokenExpiry = new Date().getTime() + 3600000
      const validTokenExpiry = tokenExpiry / 1000

      when(authenticationStoreMock.getItem(apiKeyNames.idToken)).thenReturn(
        'dummy_id_token',
      )
      when(
        authenticationStoreMock.getItem(apiKeyNames.refreshToken),
      ).thenReturn('dummy_refresh_token')
      when(authenticationStoreMock.getItem(apiKeyNames.tokenExpiry)).thenReturn(
        validTokenExpiry.toString(),
      )

      const idToken = await userClient.getLatestAuthToken()
      expect(idToken).toBe('dummy_id_token')
    })

    it('should return empty token - user not signed in', async () => {
      const empty = ''
      when(authenticationStoreMock.getItem(apiKeyNames.idToken)).thenReturn(
        empty,
      )
      when(
        authenticationStoreMock.getItem(apiKeyNames.refreshToken),
      ).thenReturn(empty)
      when(authenticationStoreMock.getItem(apiKeyNames.tokenExpiry)).thenReturn(
        empty,
      )

      const idToken = await userClient.getLatestAuthToken()
      expect(idToken).toBe(empty)
    })

    it('should return empty token - error encountered calling refreshTokens', async () => {
      const empty = ''
      when(authenticationStoreMock.getItem(apiKeyNames.idToken)).thenReturn(
        'id_token',
      )
      when(
        authenticationStoreMock.getItem(apiKeyNames.refreshToken),
      ).thenReturn('refresh_token')
      when(authenticationStoreMock.getItem(apiKeyNames.tokenExpiry)).thenReturn(
        '100',
      )

      when(identityProviderMock.refreshTokens('refresh_token')).thenReject()

      const idToken = await userClient.getLatestAuthToken()
      expect(idToken).toBe(empty)
    })
  })

  describe('globalSignOut()', () => {
    it('should complete successfully', async () => {
      let isSignedOut = false
      when(authenticationStoreMock.getItem(apiKeyNames.idToken)).thenReturn(
        'dummy_id_token',
      )
      when(authenticationStoreMock.getItem(apiKeyNames.accessToken)).thenReturn(
        'dummy_access_token',
      )
      when(
        authenticationStoreMock.getItem(apiKeyNames.refreshToken),
      ).thenReturn('dummy_refresh_token')
      when(authenticationStoreMock.getItem(apiKeyNames.tokenExpiry)).thenReturn(
        Number(new Date().getTime() + 60 * 1000).toString(),
      )
      when(
        authenticationStoreMock.getItem(apiKeyNames.refreshTokenExpiry),
      ).thenReturn(
        Number(new Date().getTime() + 60 * 60 * 1000 + 10000).toString(),
      )
      await userClient.globalSignOut()
      isSignedOut = true
      expect(isSignedOut).toBeTruthy()
    })

    it('should fail if not signed in', async () => {
      try {
        await userClient.globalSignOut()
        fail('Expected error not thrown.')
      } catch (error) {
        expect(error.name).toMatch('NotSignedInError')
      }
    })
  })

  describe('presentSignOutUI()', () => {
    it('should fail trying to invoke signout url - attempt to launch UI with window.open', async () => {
      const authUI = new CognitoAuthUI(
        authenticationStore,
        config.federatedSignIn,
        logger,
      )
      userClient.setAuthUI(authUI)

      try {
        userClient.presentSignOutUI()
        fail('Expected error not thrown.')
      } catch (error) {
        expect(error).toBeDefined()
      }
    })
  })

  describe('isSignedIn()', () => {
    it('should complete successfully', async () => {
      when(authenticationStoreMock.getItem(apiKeyNames.idToken)).thenReturn(
        'dummy_id_token',
      )
      when(authenticationStoreMock.getItem(apiKeyNames.accessToken)).thenReturn(
        'dummy_access_token',
      )
      when(
        authenticationStoreMock.getItem(apiKeyNames.refreshToken),
      ).thenReturn('dummy_refresh_token')
      when(authenticationStoreMock.getItem(apiKeyNames.tokenExpiry)).thenReturn(
        Number(new Date().getTime() + 60 * 1000).toString(),
      )
      when(
        authenticationStoreMock.getItem(apiKeyNames.refreshTokenExpiry),
      ).thenReturn(
        Number(new Date().getTime() + 60 * 60 * 1000 + 10000).toString(),
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

      const decoded: any = JWT.decode(token, { complete: true })
      expect(decoded.header['kid']).toBe('dummy_key_id')

      const verified: any = JWT.verify(token, keyPair.publicKey, {
        issuer: 'client_system_test_iss',
        audience: 'identity-service',
        subject: 'dummy_username',
        algorithms: ['RS256'],
      })

      expect(verified).toBeTruthy()

      const authUIMock: CognitoAuthUI = mock()
      const authUI = instance(authUIMock)
      userClient.setAuthUI(authUI)

      const idToken =
        'eyJraWQiOiJ3YzlaekU1eDJMT1BvZVV1XC9cL1JPWnZCV3ozbU1Zem15bXJDTFhYTmRvcms9IiwiYWxnIjoiUlMyNTYifQ.eyJjdXN0b206b2dfaWRlbnRpdHlJZCI6InVzLWVhc3QtMTo4MzE3MThmNC00MzFlLTQ0MDgtYjM0Yi02YmM3MWZjNDJmZmIiLCJzdWIiOiIxMzA4MGI0OS1jMjc3LTQ4M2QtOGQ0Zi0yZGVmZGIyNjE0ZDQiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9aaVBEVG9GNzMiLCJjb2duaXRvOnVzZXJuYW1lIjoiU3Vkb1VzZXItMGNhZmYzNzEtMjc4Zi00ODE0LWE4NjQtN2NhMTdmYWU2ODg1IiwiY3VzdG9tOnVzZXJUeXBlIjoiVEVTVCIsImF1ZCI6IjEyMHE5MDRtcmE5ZDVsNHBzbXZkYnJnbTQ5IiwiY3VzdG9tOmVudGl0bGVtZW50c1NldCI6ImR1bW15X2VudGl0bGVtZW50c19zZXQiLCJldmVudF9pZCI6Ijg2YzFhZDFkLTMwNDItNDFjMC05OTVmLTQ3ZTM0NWNjMjUxZCIsImN1c3RvbTpvZ19zdWIiOiIxMzA4MGI0OS1jMjc3LTQ4M2QtOGQ0Zi0yZGVmZGIyNjE0ZDQiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyMjQyNzA5NywiY3VzdG9tOmlkZW50aXR5SWQiOiJ1cy1lYXN0LTE6ODMxNzE4ZjQtNDMxZS00NDA4LWIzNGItNmJjNzFmYzQyZmZiIiwiZXhwIjoxNjIyNDMwNzAyLCJpYXQiOjE2MjI0MjcxMDJ9.WfhwPvhZn9STh4BSMI_w9PIx9YmAKqEyCJYuJ8NDJCfbATtwSt3QRyYILMjx6mY8IYgnEwyfoDu3Lz5-fb2tBCANz4lykW5lzS7-FxCZ2Ba4Ywr89b2cCayp3Aw3dVSHwwPtFu7-odwnHR9tpZd7jHeIVBlKQIn0WLppRTU9H1AIJh8Pq9FS6YK7uIFaOmNZxe_S18HlT8GQJNwqPZk4P8QEVyazKN9fKidO8EcQVrJoCZnJHCPP9hzum7yo2HJWvWhhlN2Si-VnqfCwDG4hpig9NcCUkGbrOYKCpDjCRZhBhcnpec310X8Lf3Qya8wZEFs1IcYHnhdKpfX4A1DYLQ'
      when(
        identityProviderMock.signInWithToken(
          'dummy_username',
          anyString(),
          'FSSO',
        ),
      ).thenResolve({
        idToken,
        accessToken: 'dummy_access_token',
        refreshToken: 'dummy_refresh_token',
        tokenExpiry: 1,
      })

      when(authenticationStoreMock.getItem(apiKeyNames.idToken)).thenReturn(
        idToken,
      )

      const tokens = await userClient.signInWithAuthenticationProvider(
        authenticationProvider,
      )

      expect(tokens.idToken).toBe(idToken)
      expect(tokens.accessToken).toBe('dummy_access_token')
      expect(tokens.refreshToken).toBe('dummy_refresh_token')
      expect(tokens.tokenExpiry).toBe(1)
      expect(userClient.getUserClaim('custom:identityId')).toBeTruthy()
    })
  })
})
