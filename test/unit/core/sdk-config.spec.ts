import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import { getIdentityServiceConfig } from '../../../src/core/sdk-config'
import { IdentityServiceConfigNotFoundError } from '../../../src/user/error'

const testFederatedSignInConfig = {
  appClientId: '120q904mra9d5l4psmvdbrgm49',
  signInRedirectUri: 'http://localhost:3000/callback',
  signOutRedirectUri: 'http://localhost:3000/',
  webDomain: 'id-dev-fsso-sudoplatform.auth.us-east-1.amazoncognito.com',
}
const testIdentityServiceConfig = {
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
}

describe('sdk-config tests', () => {
  describe('getIdentityServiceConfig', () => {
    it('should throw IdentityServiceConfigNotFoundError if identityService stanza not present in config', () => {
      DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify({
          federatedSignIn: testFederatedSignInConfig,
        }),
      )

      expect(() => getIdentityServiceConfig()).toThrowError(
        IdentityServiceConfigNotFoundError,
      )
    })

    it('should return identityServiceConfig without FSSO config', () => {
      DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify({
          identityService: testIdentityServiceConfig,
        }),
      )

      expect(getIdentityServiceConfig()).toEqual({
        identityService: testIdentityServiceConfig,
      })
    })

    it('should return identityServiceConfig with FSSO config', () => {
      DefaultConfigurationManager.getInstance().setConfig(
        JSON.stringify({
          identityService: testIdentityServiceConfig,
          federatedSignIn: testFederatedSignInConfig,
        }),
      )

      expect(getIdentityServiceConfig()).toEqual({
        identityService: testIdentityServiceConfig,
        federatedSignIn: testFederatedSignInConfig,
      })
    })
  })
})
