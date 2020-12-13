import { DefaultSudoUserClient } from '../../src/user/user-client'
import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import { TESTAuthenticationProvider } from '../../src/user/auth-provider'
import privateKeyParam from '../../config/register_key.json'
import config from '../../config/sudoplatformconfig.json'

const globalAny: any = global
globalAny.WebSocket = require('ws')
require('isomorphic-fetch')

process.env.LOG_LEVEL = 'info'
process.env.PROJECT_NAME = 'SudoUser'

DefaultConfigurationManager.getInstance().setConfig(JSON.stringify(config))
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
      expect(authTokens.idToken).toBe(userClient.getIdToken())

      // Verify refresh token expiry
      const refreshTokenExpiry = userClient.getRefreshTokenExpiry()

      expect(refreshTokenExpiry).toBeDefined()
      expect(refreshTokenExpiry.getTime()).toBeGreaterThan(
        new Date().getTime() + 60 * 24 * 60 * 60 * 1000 - 10000,
      )
      expect(refreshTokenExpiry.getTime()).toBeLessThan(
        new Date().getTime() + 60 * 24 * 60 * 60 * 1000 + 10000,
      )

      expect(await userClient.isSignedIn()).toBeTruthy()

      // Deregister
      await userClient.deregister()
      expect(await userClient.isRegistered()).toBeFalsy()

      // Reset the client internal state
      userClient.reset()
      expect(await userClient.isSignedIn()).toBeFalsy()
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

      // Reset the client internal state
      userClient.reset()
      expect(await userClient.isSignedIn()).toBeFalsy()
    }, 30000)
  })

  describe('testRegisterInvalidKeyId()', () => {
    it('should fail with test registration error', async () => {
      // Register
      const privateKeyJson = JSON.parse(JSON.stringify(privateKeyParam))
      const params: [1] = privateKeyJson['Parameters']
      const param = JSON.parse(JSON.stringify(params[0]))
      const privateKey = param.Value

      const testAuthenticationProvider = new TESTAuthenticationProvider(
        'SudoUser',
        privateKey,
        'invalid_key_id',
      )

      try {
        await userClient.registerWithAuthenticationProvider(
          testAuthenticationProvider,
          'dummy_rid',
        )
        fail('Expected error not thrown.')
      } catch (err) {
        expect(err.name).toMatch('NotAuthorizedError')
      }

      // Reset the client internal state
      userClient.reset()
    }, 30000)
  })
})
