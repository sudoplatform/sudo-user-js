import * as t from 'io-ts'

const identityService = t.intersection([
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
])

const federatedSignIn = t.intersection([
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
])

export const Config = t.type({
  identityService,
  federatedSignIn,
})

export type Config = t.TypeOf<typeof Config>
