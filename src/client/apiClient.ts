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
import { ApolloError } from 'apollo-client'
import { graphQLErrorsToClientError } from './transformer/ErrorTransformer'

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

  public async resetUserData(): Promise<{ success: boolean }> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.mutate<ResetMutation>({
        mutation: ResetDocument,
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      const apolloError = err as ApolloError
      const error = apolloError.graphQLErrors?.[0]
      if (error) {
        throw graphQLErrorsToClientError(error, this.logger)
      } else {
        throw new UnknownGraphQLError(err)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw graphQLErrorsToClientError(error, this.logger)
    }

    if (result.data) {
      return { success: result.data.reset?.success ? true : false }
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
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      const apolloError = err as ApolloError
      const error = apolloError.graphQLErrors?.[0]
      if (error) {
        throw graphQLErrorsToClientError(error, this.logger)
      } else {
        throw new UnknownGraphQLError(err)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw graphQLErrorsToClientError(error, this.logger)
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
        throw graphQLErrorsToClientError(error, this.logger)
      } else {
        throw new UnknownGraphQLError(err)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw graphQLErrorsToClientError(error, this.logger)
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
        throw graphQLErrorsToClientError(error, this.logger)
      } else {
        throw new UnknownGraphQLError(err)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw graphQLErrorsToClientError(error, this.logger)
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

  public async reset(): Promise<void> {
    await this.client.clearStore()
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
}
