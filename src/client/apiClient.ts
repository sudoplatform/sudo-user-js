/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  DeregisterMutation,
  DeregisterDocument,
  RegisterFederatedIdMutation,
  RegisterFederatedIdDocument,
  RegisterFederatedIdInput,
  GlobalSignOutMutation,
  GlobalSignOutDocument,
  ResetMutation,
  ResetDocument,
} from '../gen/graphql-types'
import {
  NotSignedInError,
  FatalError,
  UnknownGraphQLError,
  Logger,
} from '@sudoplatform/sudo-common'
import { SudoUserClient } from '../user/user-client-interface'

import { graphQLErrorsToClientError } from './transformer/ErrorTransformer'
import { AmplifyClient } from './amplifyClient'

/**
 * AppSync wrapper to use to invoke Identity Service APIs.
 */
export class ApiClient {
  private client: AmplifyClient
  private region: string
  private graphqlUrl: string
  private sudoUserClient: SudoUserClient
  private logger: Logger

  public constructor(
    region: string,
    graphqlUrl: string,
    sudoUserClient: SudoUserClient,
    logger: Logger,
  ) {
    this.region = region
    this.graphqlUrl = graphqlUrl
    this.sudoUserClient = sudoUserClient
    this.logger = logger

    this.client = new AmplifyClient({
      graphqlUrl,
      region: region,
      tokenProvider: async () => await sudoUserClient.getLatestAuthToken(),
    })
  }

  public async resetUserData(): Promise<{ success: boolean }> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.mutate<ResetMutation>({
        mutation: ResetDocument,
      })
    } catch (err: unknown) {
      if ('graphQLErrors' in (err as any)) {
        const error = (err as any).graphQLErrors?.[0]
        if (error) {
          throw graphQLErrorsToClientError(error, this.logger)
        } else {
          throw new UnknownGraphQLError(err)
        }
      }
    }

    const error = result?.errors?.[0]
    if (error) {
      throw graphQLErrorsToClientError(error, this.logger)
    }

    if (result?.data) {
      return { success: !!result.data.reset?.success }
    } else {
      throw new FatalError('reset did not return any result.')
    }
  }

  public async deregister(): Promise<{ success: boolean }> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.mutate<DeregisterMutation>({
        mutation: DeregisterDocument,
      })
    } catch (err) {
      if ('graphQLErrors' in (err as any)) {
        const error = (err as any).graphQLErrors?.[0]
        if (error) {
          throw graphQLErrorsToClientError(error, this.logger)
        } else {
          throw new UnknownGraphQLError(err)
        }
      }
    }

    const error = result?.errors?.[0]
    if (error) {
      throw graphQLErrorsToClientError(error, this.logger)
    }

    if (result?.data) {
      return { success: !!result?.data.deregister?.success }
    } else {
      throw new FatalError('deregister did not return any result.')
    }
  }

  public async globalSignOut(): Promise<{ success: boolean }> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.mutate<GlobalSignOutMutation>({
        mutation: GlobalSignOutDocument,
      })
    } catch (err) {
      if ('graphQLErrors' in (err as any)) {
        const error = (err as any).graphQLErrors?.[0]
        if (error) {
          throw graphQLErrorsToClientError(error, this.logger)
        } else {
          throw new UnknownGraphQLError(err)
        }
      }
    }

    const error = result?.errors?.[0]
    if (error) {
      throw graphQLErrorsToClientError(error, this.logger)
    }

    if (result?.data) {
      return { success: result?.data.globalSignOut?.success ?? false }
    } else {
      throw new FatalError('globalSignOut did not return any result.')
    }
  }

  public async registerFederatedId(
    input: RegisterFederatedIdInput,
  ): Promise<{ identityId: string }> {
    let result
    try {
      result = await this.client.mutate<RegisterFederatedIdMutation>({
        mutation: RegisterFederatedIdDocument,
        variables: { input },
      })
    } catch (err) {
      if ('graphQLErrors' in (err as any)) {
        const error = (err as any).graphQLErrors?.[0]
        if (error) {
          throw graphQLErrorsToClientError(error, this.logger)
        } else {
          throw new UnknownGraphQLError(err)
        }
      }
    }

    const error = result?.errors?.[0]
    if (error) {
      throw graphQLErrorsToClientError(error, this.logger)
    }

    const identityId = result?.data?.registerFederatedId?.identityId
    if (identityId) {
      return {
        identityId,
      }
    } else {
      throw new FatalError(
        'registerFederatedId did not return expected result.',
      )
    }
  }

  public async reset(): Promise<void> {
    this.client = new AmplifyClient({
      graphqlUrl: this.graphqlUrl,
      region: this.region,
      tokenProvider: async () => await this.sudoUserClient.getLatestAuthToken(),
    })
  }
}
