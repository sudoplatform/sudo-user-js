import { DefaultSudoUserClient } from '../../src/user/user-client'
import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import { TESTAuthenticationProvider } from '../../src/user/auth-provider'
import privateKeyParam from '../../system-test-config/anonyome_ssm_parameter_register_key.json'

const globalAny: any = global
globalAny.WebSocket = require('ws')
require('isomorphic-fetch')

const testConfig = {
  federatedSignIn: {
    appClientId: '120q904mra9d5l4psmvdbrgm49',
    signInRedirectUri: 'http://localhost:3000/callback',
    signOutRedirectUri: 'http://localhost:3000/',
    webDomain: 'id-dev-fsso-sudoplatform.auth.us-east-1.amazoncognito.com',
    identityProvider: 'Auth0',
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

DefaultConfigurationManager.getInstance().setConfig(JSON.stringify(testConfig))
const userClient = new DefaultSudoUserClient()

describe('SudoUserClient', () => {
  describe('testRegister()', () => {
    it('should complete successfully', async () => {
      // Register
      const privateKeyJson = JSON.parse(JSON.stringify(privateKeyParam))
      const params: [1] = privateKeyJson['Parameters']
      const param = JSON.parse(JSON.stringify(params[0]))
      const privateKey = param.Value

      const testAuthenticationProvider = new TESTAuthenticationProvider(
        'SudoUser',
        privateKey,
      )

      await userClient.registerWithAuthenticationProvider(
        testAuthenticationProvider,
        'dummy_rid',
      )
      expect(await userClient.isRegistered()).toBeTruthy()

      // Sign in using private key
      const authTokens = await userClient.signInWithKey()

      expect(authTokens).toBeDefined()
      expect(authTokens.idToken).toBeDefined()

      expect(await userClient.isSignedIn()).toBeTruthy()

      // Deregister
      await userClient.deregister()
      expect(await userClient.isRegistered()).toBeFalsy()
    }, 30000)
  })

  describe('testRegisterAndClearAuthTokens()', () => {
    it('should complete successfully', async () => {
      // Register
      const privateKeyJson = JSON.parse(JSON.stringify(privateKeyParam))
      const params: [1] = privateKeyJson['Parameters']
      const param = JSON.parse(JSON.stringify(params[0]))
      const privateKey = param.Value

      const testAuthenticationProvider = new TESTAuthenticationProvider(
        'SudoUser',
        privateKey,
      )

      await userClient.registerWithAuthenticationProvider(
        testAuthenticationProvider,
        'dummy_rid',
      )
      expect(await userClient.isRegistered()).toBeTruthy()

      // Sign in using private key
      const authTokens = await userClient.signInWithKey()

      expect(authTokens).toBeDefined()
      expect(authTokens.idToken).toBeDefined()

      expect(await userClient.isSignedIn()).toBeTruthy()

      // clear auth tokens (local sign out)
      userClient.clearAuthenticationTokens()
      expect(await userClient.isSignedIn()).toBeFalsy()

      // Sign in again so we can call deregister
      await userClient.signInWithKey()
      expect(await userClient.isSignedIn()).toBeTruthy()

      // Deregister
      await userClient.deregister()
      expect(await userClient.isRegistered()).toBeFalsy()
    }, 30000)
  })
})
