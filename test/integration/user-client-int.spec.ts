import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import { existsSync, readFileSync } from 'fs'
import { v4 } from 'uuid'
import privateKeyParam from '../../config/register_key.json'
import config from '../../config/sudoplatformconfig.json'
import {
  LocalAuthenticationProvider,
  TESTAuthenticationProvider,
} from '../../src/user/auth-provider'
import { DefaultSudoUserClient } from '../../src/user/user-client'

const globalAny: any = global
globalAny.crypto = require('isomorphic-webcrypto')
globalAny.WebSocket = require('ws')
require('isomorphic-fetch')

process.env.LOG_LEVEL = 'info'
process.env.PROJECT_NAME = 'SudoUser'

DefaultConfigurationManager.getInstance().setConfig(JSON.stringify(config))
const userClient = new DefaultSudoUserClient({})

async function registerAndSignIn() {
  // Register
  const privateKeyJson = JSON.parse(JSON.stringify(privateKeyParam))
  const params: [1] = privateKeyJson['Parameters']
  const param = JSON.parse(JSON.stringify(params[0]))
  const privateKey = param.Value

  const testAuthenticationProvider = new TESTAuthenticationProvider(
    'SudoUser',
    privateKey,
    'register_key',
    { 'custom:entitlementsSet': 'dummy_entitlements_set' },
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

  expect(userClient.getUserClaim('custom:entitlementsSet')).toBe(
    'dummy_entitlements_set',
  )
}

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
        'register_key',
        { 'custom:entitlementsSet': 'dummy_entitlements_set' },
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

      expect(userClient.getUserClaim('custom:entitlementsSet')).toBe(
        'dummy_entitlements_set',
      )

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

  describe('testRegisterAndRefreshTokens()', () => {
    it('should complete successfully', async () => {
      await registerAndSignIn()

      // Refresh the tokens
      const refreshedTokens = await userClient.refreshTokens(
        userClient.getRefreshToken(),
      )
      const refreshedIdToken = userClient.getIdToken()
      expect(refreshedIdToken).toBe(refreshedTokens.idToken)

      // Deregister
      await userClient.deregister()
      expect(await userClient.isRegistered()).toBeFalsy()

      // Reset the client internal state
      userClient.reset()
      expect(await userClient.isSignedIn()).toBeFalsy()
    }, 30000)

    it('should fail invoking refreshTokens', async () => {
      await registerAndSignIn()

      // Refresh the tokens
      try {
        await userClient.refreshTokens('invalid_token')
        fail('Expected error not thrown.')
      } catch (error) {
        expect(error.name).toMatch('AuthenticationError')
      }

      // Deregister
      await userClient.deregister()
      expect(await userClient.isRegistered()).toBeFalsy()

      // Reset the client internal state
      userClient.reset()
      expect(await userClient.isSignedIn()).toBeFalsy()
    }, 30000)
  })

  describe('testCustomFSSO()', () => {
    const keyPath = 'config/fsso.key'
    const keyIdPath = 'config/fsso.id'
    if (existsSync(keyPath) && existsSync(keyIdPath)) {
      it('should complete successfully', async () => {
        const key = readFileSync(keyPath, 'ascii').trim()
        const keyId = readFileSync(keyIdPath, 'ascii').trim()
        const username = `sudouser-fsso-test-${v4()}`

        const authenticationProvider = new LocalAuthenticationProvider(
          'client_system_test_iss',
          key,
          keyId,
          username,
          { 'custom:entitlementsSet': 'dummy_entitlements_set' },
        )

        const uid = await userClient.registerWithAuthenticationProvider(
          authenticationProvider,
          'dummy_rid',
        )

        expect(userClient.isRegistered()).toBeTruthy()
        expect(uid).toBe(username)

        try {
          await userClient.registerWithAuthenticationProvider(
            authenticationProvider,
            'dummy_rid',
          )
          fail('Expected error not thrown.')
        } catch (err) {
          expect(err.name).toMatch('AlreadyRegisteredError')
        }

        await userClient.signInWithAuthenticationProvider(
          authenticationProvider,
        )

        expect(userClient.isSignedIn()).toBeTruthy()
        expect(userClient.getUserClaim('custom:entitlementsSet')).toBe(
          'dummy_entitlements_set',
        )

        await userClient.deregister()
      }, 30000)
    } else {
      it('skip test.', () => {
        console.log(
          'No sudoplatformconfig.json, key and key ID file found. Skipping tests.',
        )
      })
    }
  })
})
