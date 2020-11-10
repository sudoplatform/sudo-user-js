import * as t from 'io-ts'

export const Config = t.type({
  identityService: t.type({
    region: t.string,
    poolId: t.string,
    clientId: t.string,
    identityPoolId: t.string,
    apiUrl: t.string,
    apiKey: t.string,
    bucket: t.string,
    transientBucket: t.string,
    refreshTokenLifetime: t.number,
    registrationMethods: t.array(t.string),
  }),
  federatedSignIn: t.type({
    appClientId: t.string,
    signInRedirectUri: t.string,
    signOutRedirectUri: t.string,
    webDomain: t.string,
    identityProvider: t.string,
    refreshTokenLifetime: t.number,
  }),
})

export type Config = t.TypeOf<typeof Config>
