import { AuthUI, CognitoAuthUI } from '../../src/user/auth'
import { DefaultSudoUserClient } from '../../src/user/user-client'
import { Config } from '../../src/core/sdk-config'
import { AuthenticationStore } from '../../src/core/auth-store'
import { mock, instance, when, reset, anyString } from 'ts-mockito'
import * as JWT from 'jsonwebtoken'
import { generateKeyPairSync } from 'crypto'
import { KeyPairKey, PrivateKey } from '../../src/utils/key-pair'
import { apiKeyNames } from '../../src/core/api-key-names'
import { KeyManager } from '../../src/core/key-manager'
import {
  DefaultConfigurationManager,
  DefaultLogger,
} from '@sudoplatform/sudo-common'
import { generateKeyPair } from 'crypto'
import { promisify } from 'util'
import { LocalAuthenticationProvider } from '../../src/user/auth-provider'
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
const authenticationStoreMock: AuthenticationStore = mock()
const authenticationStore = instance(authenticationStoreMock)
const keyManagerMock: KeyManager = mock()
const keyManager = instance(keyManagerMock)
DefaultConfigurationManager.getInstance().setConfig(JSON.stringify(testConfig))
const userClient = new DefaultSudoUserClient(keyManager, authUI)
const config = DefaultConfigurationManager.getInstance().bindConfigSet<Config>(
  Config,
  undefined,
)
const logger = new DefaultLogger()

afterEach((): void => {
  reset(authUIMock)
  reset(authenticationStoreMock)
  userClient.setAuthUI(authUI)
})

describe('SudoUserClient', () => {
  describe('presentFederatedSignInUI()', () => {
    it('should fail with authentication error - default launchUri - attempt to launch UI with window.open', async () => {
      const authUI = new CognitoAuthUI(
        authenticationStore,
        keyManager,
        config,
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
        keyManager,
        config,
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
      when(authUIMock.getIdToken()).thenReturn(token)
      const sub = userClient.getSubject()
      expect(sub).toBe('dummy_sub')
    })
  })

  describe('getUserName()', () => {
    it('should complete successfully', async () => {
      const authUI = new CognitoAuthUI(
        authenticationStore,
        keyManager,
        config,
        logger,
      )
      userClient.setAuthUI(authUI)

      when(authenticationStoreMock.getItem(apiKeyNames.userId)).thenReturn(
        'test_user',
      )

      const userName = userClient.getUserName()
      expect(userName).toBe('test_user')
    })
  })

  describe('refreshTokens()', () => {
    it('should complete successfully', async () => {
      when(authUIMock.refreshTokens('refresh_token')).thenResolve({
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
      when(authUIMock.refreshTokens('refresh_token')).thenReject()

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
        keyManager,
        config,
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
      const authUI = new CognitoAuthUI(
        authenticationStore,
        keyManager,
        config,
        logger,
      )
      userClient.setAuthUI(authUI)

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
  })

  describe('globalSignOut()', () => {
    it('should complete successfully', async () => {
      let isSignedOut = false
      when(authUIMock.getAccessToken()).thenReturn('dummy_access_token')
      when(authUIMock.globalSignOut('dummy_access_token')).thenResolve()
      await userClient.globalSignOut()
      isSignedOut = true
      expect(isSignedOut).toBeTruthy()
    })

    it('should fail with signout error - invalid access token', async () => {
      const authUI = new CognitoAuthUI(
        authenticationStore,
        keyManager,
        config,
        logger,
      )
      userClient.setAuthUI(authUI)

      when(authenticationStoreMock.getItem(apiKeyNames.accessToken)).thenReturn(
        'invalid_access_token',
      )

      try {
        await userClient.globalSignOut()
        fail('Expected error not thrown.')
      } catch (error) {
        expect(error.name).toMatch('SignOutError')
      }
    })
  })

  describe('presentSignOutUI()', () => {
    it('should fail trying to invoke signout url - attempt to launch UI with window.open', async () => {
      const authUI = new CognitoAuthUI(
        authenticationStore,
        keyManager,
        config,
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
      const authUI = new CognitoAuthUI(
        authenticationStore,
        keyManager,
        config,
        logger,
      )
      userClient.setAuthUI(authUI)

      when(authenticationStoreMock.getItem(apiKeyNames.idToken)).thenReturn(
        'dummy_id_token',
      )
      when(authenticationStoreMock.getItem(apiKeyNames.accessToken)).thenReturn(
        'dummy_access_token',
      )
      when(
        authenticationStoreMock.getItem(apiKeyNames.refreshTokenExpiry),
      ).thenReturn(
        Number(new Date().getTime() + 60 * 60 * 1000 + 10000).toString(),
      )
      expect(userClient.isSignedIn()).toBeTruthy()
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

      when(
        authUIMock.signInWithToken('dummy_username', anyString(), 'FSSO'),
      ).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
        refreshToken: 'dummy_refresh_token',
        tokenExpiry: 1,
      })

      const tokens = await userClient.signInWithAuthenticationProvider(
        authenticationProvider,
      )

      expect(tokens.idToken).toBe('dummy_id_token')
      expect(tokens.accessToken).toBe('dummy_access_token')
      expect(tokens.refreshToken).toBe('dummy_refresh_token')
      expect(tokens.tokenExpiry).toBe(1)
    })
  })
})
