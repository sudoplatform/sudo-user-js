/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { NormalizedCacheObject } from 'apollo-cache-inmemory'
import { AWSAppSyncClient, AUTH_TYPE } from 'aws-appsync'
import {
  DeregisterMutation,
  DeregisterDocument,
  RegisterFederatedIdMutation,
  RegisterFederatedIdDocument,
  RegisterFederatedIdInput,
  GlobalSignOutMutation,
  GlobalSignOutDocument,
} from '../gen/graphql-types'
import {
  NotSignedInError,
  FatalError,
  ServiceError,
  UnknownGraphQLError,
  AppSyncError,
  Logger,
  NotAuthorizedError,
} from '@sudoplatform/sudo-common'
import { SudoUserClient } from '../user/user-client-interface'
import { ApolloError } from 'apollo-client'

/**
 * AppSync wrapper to use to invoke Identity Service APIs.
 */
export class ApiClient {
  private client: AWSAppSyncClient<NormalizedCacheObject>
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

    this.client = new AWSAppSyncClient({
      url: graphqlUrl,
      region: region,
      auth: {
        type: AUTH_TYPE.AMAZON_COGNITO_USER_POOLS,
        jwtToken: async () => await sudoUserClient.getLatestAuthToken(),
      },
      disableOffline: true,
    })
  }

  public async deregister(): Promise<{ success: boolean }> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.mutate<DeregisterMutation>({
        mutation: DeregisterDocument,
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      const apolloError = err as ApolloError
      const error = apolloError.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(err)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      return { success: result.data.deregister?.success ? true : false }
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
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      const apolloError = err as ApolloError
      const error = apolloError.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(err)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      return { success: result.data.globalSignOut?.success ? true : false }
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
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      const apolloError = err as ApolloError
      const error = apolloError.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(err)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    const identityId = result.data?.registerFederatedId?.identityId
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

  public reset(): void {
    this.client.clearStore()
    this.client = new AWSAppSyncClient({
      url: this.graphqlUrl,
      region: this.region,
      auth: {
        type: AUTH_TYPE.AMAZON_COGNITO_USER_POOLS,
        jwtToken: async () => await this.sudoUserClient.getLatestAuthToken(),
      },
      disableOffline: true,
    })
  }

  private graphQLErrorsToClientError(error: AppSyncError): Error {
    this.logger.error('GraphQL call failed.', { error })

    if (error.errorType === 'sudoplatform.ServiceError') {
      return new ServiceError(error.message)
    } else if (
      error.errorType === 'sudoplatform.identity.TokenValidationError'
    ) {
      return new NotAuthorizedError()
    } else {
      return new UnknownGraphQLError(error)
    }
  }
}
