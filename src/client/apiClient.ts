import { NormalizedCacheObject } from 'apollo-cache-inmemory'
import { AWSAppSyncClient, AUTH_TYPE } from 'aws-appsync'
import { DeregisterMutation, DeregisterDocument } from '../gen/graphql-types'
import {
  NotSignedInError,
  FatalError,
  ServiceError,
  UnknownGraphQLError,
  AppSyncError,
  Logger,
} from '@sudoplatform/sudo-common'
import { SudoUserClient } from '../user/user-client-interface'

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
      const error = err.graphQLErrors?.[0]
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
    } else {
      return new UnknownGraphQLError(error)
    }
  }
}
