/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  AppSyncError,
  Logger,
  NotAuthorizedError,
  ServiceError,
  UnknownGraphQLError,
} from '@sudoplatform/sudo-common'

export function graphQLErrorsToClientError(
  error: AppSyncError,
  logger: Logger,
): Error {
  logger.error('GraphQL call failed.', { error })

  if (error.errorType === 'sudoplatform.ServiceError') {
    return new ServiceError(error.message)
  } else if (error.errorType === 'sudoplatform.identity.TokenValidationError') {
    return new NotAuthorizedError()
  } else {
    return new UnknownGraphQLError(error)
  }
}
