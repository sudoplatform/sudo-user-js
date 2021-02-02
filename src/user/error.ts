/**
 * Indicates the user associated with the client is already registered.
 */
export class AlreadyRegisteredError extends Error {
  constructor() {
    super('User is already registered.')
    this.name = 'AlreadyRegisteredError'
  }
}
