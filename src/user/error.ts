/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

class UserError extends Error {
  constructor(msg?: string) {
    super(msg)
    this.name = this.constructor.name
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor)
    }
  }
}

/**
 * Indicates the user associated with the client is already registered.
 */
export class AlreadyRegisteredError extends UserError {
  constructor() {
    super('User is already registered.')
  }
}

/**
 * Indicates the configuration related to Identity Service is not found. This may indicate that Identity Service
 * is not deployed into your runtime instance or the config file that
 * you are using is invalid.
 */
export class IdentityServiceConfigNotFoundError extends UserError {
  constructor() {
    super('Identity service configuration not found.')
  }
}
