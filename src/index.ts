/* Everything exported here is considered public API and is documented by typedoc. */
export { DefaultSudoUserClient } from './user/user-client'
export * from './user/user-client-interface'
export {
  TESTAuthenticationProvider,
  LocalAuthenticationProvider,
  AuthenticationProvider,
} from './user/auth-provider'

export * from './user/error'

/*
 * Private interfaces for support for other Sudo Platform
 * SDKs.
 */
export * as internal from './core/sdk-config'
