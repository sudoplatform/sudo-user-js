import {
  AuthenticationError,
  DefaultConfigurationManager,
  NotAuthorizedError,
} from '@sudoplatform/sudo-common'
import { existsSync, readFileSync } from 'fs'
import { v4 } from 'uuid'
import {
  LocalAuthenticationProvider,
  TESTAuthenticationProvider,
} from '../../src/user/auth-provider'
import { AlreadyRegisteredError } from '../../src/user/error'
import { DefaultSudoUserClient } from '../../src/user/user-client'
import fs from 'fs'
import { Config } from '../../src/core/sdk-config'
import { DefaultRefreshTokenLifetime } from '../../src/user/auth'

const globalAny: any = global
globalAny.crypto = require('isomorphic-webcrypto')
globalAny.WebSocket = require('ws')
require('isomorphic-fetch')

process.env.LOG_LEVEL = 'info'
process.env.PROJECT_NAME = 'SudoUser'

const registerPrivateKey = fs
  .readFileSync(`${__dirname}/../../config/register_key.private`)
  .toString('utf-8')
  .trim()

const registerKeyId = fs
  .readFileSync(`${__dirname}/../../config/register_key.id`)
  .toString('utf-8')
  .trim()

const configFileContents = fs
  .readFileSync(`${__dirname}/../../config/sudoplatformconfig.json`)
  .toString('utf-8')
  .trim()

DefaultConfigurationManager.getInstance().setConfig(configFileContents)
const config = DefaultConfigurationManager.getInstance().bindConfigSet(
  Config,
  undefined,
) as Config

const userClient = new DefaultSudoUserClient({})

const refreshTokenLifetime =
  config.identityService.refreshTokenLifetime ?? DefaultRefreshTokenLifetime

afterEach(async () => {
  await userClient.sudoKeyManager.removeAllKeys()
})

async function registerAndSignIn() {
  const testAuthenticationProvider = new TESTAuthenticationProvider(
    'SudoUser',
    registerPrivateKey,
    registerKeyId,
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
  expect(authTokens.idToken).toBe(await userClient.getIdToken())

  // Verify refresh token expiry
  const refreshTokenExpiry = await userClient.getRefreshTokenExpiry()

  expect(refreshTokenExpiry).toBeDefined()
  expect(refreshTokenExpiry?.getTime()).toBeGreaterThan(
    new Date().getTime() + refreshTokenLifetime * 24 * 60 * 60 * 1000 - 10000,
  )
  expect(refreshTokenExpiry?.getTime()).toBeLessThan(
    new Date().getTime() + refreshTokenLifetime * 24 * 60 * 60 * 1000 + 10000,
  )

  expect(await userClient.isSignedIn()).toBeTruthy()

  expect(await userClient.getUserClaim('custom:entitlementsSet')).toBe(
    'dummy_entitlements_set',
  )
}

describe('SudoUserClient', () => {
  describe('testRegister()', () => {
    it('should complete successfully', async () => {
      // Register
      const testAuthenticationProvider = new TESTAuthenticationProvider(
        'SudoUser',
        registerPrivateKey,
        registerKeyId,
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
      expect(authTokens.idToken).toBe(await userClient.getIdToken())

      // Verify refresh token expiry
      const refreshTokenExpiry = await userClient.getRefreshTokenExpiry()

      expect(refreshTokenExpiry).toBeDefined()
      expect(refreshTokenExpiry?.getTime()).toBeGreaterThan(
        new Date().getTime() +
          refreshTokenLifetime * 24 * 60 * 60 * 1000 -
          10000,
      )
      expect(refreshTokenExpiry?.getTime()).toBeLessThan(
        new Date().getTime() +
          refreshTokenLifetime * 24 * 60 * 60 * 1000 +
          10000,
      )

      expect(await userClient.isSignedIn()).toBeTruthy()

      expect(await userClient.getUserClaim('custom:entitlementsSet')).toBe(
        'dummy_entitlements_set',
      )

      expect(await userClient.getUserClaim('custom:identityId')).toBeTruthy()

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
      const testAuthenticationProvider = new TESTAuthenticationProvider(
        'SudoUser',
        registerPrivateKey,
        registerKeyId,
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
      await userClient.clearAuthenticationTokens()
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
      const testAuthenticationProvider = new TESTAuthenticationProvider(
        'SudoUser',
        registerPrivateKey,
        'invalid_key_id',
      )

      await expect(
        userClient.registerWithAuthenticationProvider(
          testAuthenticationProvider,
          'dummy_rid',
        ),
      ).rejects.toThrow(NotAuthorizedError)

      // Reset the client internal state
      userClient.reset()
    }, 30000)
  })

  describe('testRegisterAndRefreshTokens()', () => {
    it('should complete successfully', async () => {
      await registerAndSignIn()

      // Refresh the tokens
      const refreshToken = await userClient.getRefreshToken()
      if (!refreshToken) {
        fail('refreshToken undefined')
      }
      const refreshedTokens = await userClient.refreshTokens(refreshToken)
      const refreshedIdToken = await userClient.getIdToken()
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
      await expect(
        userClient.refreshTokens('invalid_token'),
      ).rejects.toThrowError(AuthenticationError)

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

        await expect(userClient.isRegistered()).resolves.toBeTruthy()
        expect(uid).toBe(username)

        await expect(
          userClient.registerWithAuthenticationProvider(
            authenticationProvider,
            'dummy_rid',
          ),
        ).rejects.toThrowError(AlreadyRegisteredError)

        await userClient.signInWithAuthenticationProvider(
          authenticationProvider,
        )

        await expect(userClient.isSignedIn()).resolves.toBeTruthy()
        await expect(
          userClient.getUserClaim('custom:entitlementsSet'),
        ).resolves.toBe('dummy_entitlements_set')
        await expect(
          userClient.getUserClaim('custom:identityId'),
        ).resolves.toBeTruthy()

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

  describe('globalSignOut()', () => {
    it('should complete successfully', async () => {
      await registerAndSignIn()
      await userClient.globalSignOut()
    }, 30000)
  })
})
