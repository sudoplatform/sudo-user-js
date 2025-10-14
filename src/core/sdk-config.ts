/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import * as t from 'io-ts'
import { IdentityServiceConfigNotFoundError } from '../user/error'

// eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
export const IdentityServiceConfigCodec = t.intersection(
  [
    // eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
    t.type({
      region: t.string,
      poolId: t.string,
      clientId: t.string,
      identityPoolId: t.string,
      apiUrl: t.string,
      bucket: t.string,
      transientBucket: t.string,
      // eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
      registrationMethods: t.array(t.string),
    }),
    // eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
    t.partial({
      refreshTokenLifetime: t.number,
    }),
  ],
  'IdentityServiceConfig',
)

// eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
export const FederatedSignInConfigCodec = t.intersection(
  [
    // eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
    t.type({
      appClientId: t.string,
      signInRedirectUri: t.string,
      signOutRedirectUri: t.string,
      webDomain: t.string,
    }),
    // eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
    t.partial({
      identityProvider: t.string,
      refreshTokenLifetime: t.number,
    }),
  ],
  'FederatedSignInConfig',
)

// eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
export const Config = t.intersection([
  // eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
  t.type({
    identityService: IdentityServiceConfigCodec,
  }),
  // eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
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
