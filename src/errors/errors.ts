/**
 * An error occurred during the authentication process. This may be due to invalid credentials
 * being supplied, or authentication tokens not able to be retrieved from storage.
 */
export class AuthenticationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AuthenticationError'
  }
}

/**
 * An error occurred during the sign out process.
 */
export class SignOutError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SignOutError'
  }
}

/**
 * An error occurred during the registration process.
 * This may be due to the client already being registered.
 */
export class RegisterError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RegisterError'
  }
}

/**
 * An error occurred indicating that the user is not registered.
 */
export class NotRegisteredError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NotRegisteredError'
  }
}

/**
 * An unexpected error was encountered. This may result from programmatic error
 * and is unlikley to be user recoverable.
 */
export class FatalError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FatalError'
  }
}
