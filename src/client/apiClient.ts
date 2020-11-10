import { NormalizedCacheObject } from 'apollo-cache-inmemory'
import { AWSAppSyncClient, AUTH_TYPE } from 'aws-appsync'
import { DeregisterMutation, DeregisterDocument } from '../gen/graphql-types'
import {
  NotSignedInError,
  FatalError,
  ServiceError,
  UnknownGraphQLError,
  AppSyncError,
} from '@sudoplatform/sudo-common'
import { AuthUI } from '../user/auth'

/**
 * AppSync wrapper to use to invoke Identity Service APIs.
 */
export class ApiClient {
  private client: AWSAppSyncClient<NormalizedCacheObject>
  private region: string
  private graphqlUrl: string
  private authUI: AuthUI

  public constructor(region: string, graphqlUrl: string, authUI: AuthUI) {
    this.region = region
    this.graphqlUrl = graphqlUrl
    this.authUI = authUI

    this.client = new AWSAppSyncClient({
      url: graphqlUrl,
      region: region,
      auth: {
        type: AUTH_TYPE.AMAZON_COGNITO_USER_POOLS,
        jwtToken: async () => await authUI.getLatestAuthToken(),
      },
      disableOffline: true,
    })
  }

  public async deregister(): Promise<{ success: boolean }> {
    if (!(await this.authUI.isSignedIn())) {
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
        jwtToken: async () => await this.authUI.getLatestAuthToken(),
      },
      disableOffline: true,
    })
  }

  private graphQLErrorsToClientError(error: AppSyncError): Error {
    console.log({ error }, 'GraphQL call failed.')

    if (error.errorType === 'sudoplatform.ServiceError') {
      return new ServiceError(error.message)
    } else {
      return new UnknownGraphQLError(error)
    }
  }
}
