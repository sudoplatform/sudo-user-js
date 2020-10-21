import { NormalizedCacheObject } from 'apollo-cache-inmemory'
import { AWSAppSyncClient, AUTH_TYPE } from 'aws-appsync'
import { DeregisterMutation, DeregisterDocument } from '../gen/graphql-types'
import { FatalError } from '../errors/errors'
import { AuthUI } from '../user/auth'

/**
 * AppSync wrapper to use to invoke Identity Service APIs.
 */
export class ApiClient {
  private readonly client: AWSAppSyncClient<NormalizedCacheObject>

  public constructor(region: string, graphqlUrl: string, authUI: AuthUI) {
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
    const result = await this.client.mutate<DeregisterMutation>({
      mutation: DeregisterDocument,
      fetchPolicy: 'no-cache',
    })

    if (result.data) {
      return { success: result.data.deregister?.success ? true : false }
    } else {
      throw new FatalError('deregister did not return any result.')
    }
  }
}
