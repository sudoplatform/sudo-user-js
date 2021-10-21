import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import * as t from 'io-ts'
import { IdentityServiceConfigNotFoundError } from '../user/error'

export const IdentityServiceConfigCodec = t.intersection(
  [
    t.type({
      region: t.string,
      poolId: t.string,
      clientId: t.string,
      identityPoolId: t.string,
      apiUrl: t.string,
      apiKey: t.string,
      bucket: t.string,
      transientBucket: t.string,
      registrationMethods: t.array(t.string),
    }),
    t.partial({
      refreshTokenLifetime: t.number,
    }),
  ],
  'IdentityServiceConfig',
)

export const FederatedSignInConfigCodec = t.intersection(
  [
    t.type({
      appClientId: t.string,
      signInRedirectUri: t.string,
      signOutRedirectUri: t.string,
      webDomain: t.string,
    }),
    t.partial({
      identityProvider: t.string,
      refreshTokenLifetime: t.number,
    }),
  ],
  'FederatedSignInConfig',
)

export const Config = t.intersection([
  t.type({
    identityService: IdentityServiceConfigCodec,
  }),
  t.partial({
    federatedSignIn: FederatedSignInConfigCodec,
  }),
])

export type Config = t.TypeOf<typeof Config>
export type IdentityServiceConfig = t.TypeOf<typeof IdentityServiceConfigCodec>
export type FederatedSignInConfig = t.TypeOf<typeof FederatedSignInConfigCodec>

export function getIdentityServiceConfig(): Config {
  if (
    !DefaultConfigurationManager.getInstance().getConfigSet('identityService')
  ) {
    throw new IdentityServiceConfigNotFoundError()
  }

  return DefaultConfigurationManager.getInstance().bindConfigSet<Config>(
    Config,
    undefined,
  )
}
