import { GraphQLResult, V6Client } from '@aws-amplify/api-graphql'
import {
  AmplifyClassV6,
  CredentialsAndIdentityId,
  CredentialsAndIdentityIdProvider,
  GetCredentialsOptions,
} from '@aws-amplify/core'
// Ideally we would import from 'aws-amplify' but that prevents us from a
// multi-client solution because it uses a singleton amplify instance.
import { generateClient } from '@aws-amplify/api-graphql/internals'
import { DocumentNode } from 'graphql'
import Observable from 'zen-observable'
import {
  GraphQLClient,
  GraphQLClientAuthMode,
  GraphQLClientOptions,
  IAMCredentials,
  TokenProvider,
} from './graphqlClient'

enum GraphQLAuthMode {
  OpenIDConnect = 'oidc',
  IAM = 'iam',
  ApiKey = 'apiKey',
}
/**
 *  We provide a default IAMCredentialsProvider which accesses
 *  the required environment variables for the IAM auth mode, if the values are not provided
 */
class IAMCredentialsProvider implements CredentialsAndIdentityIdProvider {
  private credentials: CredentialsAndIdentityId | undefined = undefined
  constructor(credentials?: IAMCredentials) {
    if (credentials) {
      this.credentials = { credentials, identityId: '' }
    }
  }
  clearCredentialsAndIdentityId(): void {}
  getCredentialsAndIdentityId(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _: GetCredentialsOptions,
  ): Promise<CredentialsAndIdentityId | undefined> {
    return new Promise<CredentialsAndIdentityId>((resolve) => {
      if (!this.credentials) {
        const accessKeyId = process.env.AWS_ACCESS_KEY_ID
        const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY
        if (!accessKeyId || !secretAccessKey) {
          throw new Error('AWS IAM credentials are not set')
        }
        this.credentials = {
          credentials: {
            accessKeyId: accessKeyId,
            secretAccessKey: secretAccessKey,
            sessionToken: process.env.AWS_SESSION_TOKEN,
          },
          identityId: '', // Amplify expects this but it's empty for IAM
        }
      }
      return resolve(this.credentials)
    })
  }
}

/**
 * Convenience wrapper for GraphQL API using Amplify SDK.
 */
export class AmplifyClient implements GraphQLClient {
  private readonly options: GraphQLClientOptions
  private client: V6Client
  private readonly amplify: AmplifyClassV6

  public constructor(options: GraphQLClientOptions) {
    this.options = options
    this.amplify = new AmplifyClassV6()
    this.configure(options)

    // @ts-expect-error complex typings not manageable by tsc
    this.client = generateClient({
      amplify: this.amplify,
    })
  }

  private configure(options: GraphQLClientOptions) {
    const authModeToUse =
      options.authMode ?? GraphQLClientAuthMode.OpenIDConnect
    switch (authModeToUse) {
      case GraphQLClientAuthMode.OpenIDConnect:
        if (!options.tokenProvider) {
          throw new Error(
            'tokenProvider must be provided when using OPENID_CONNECT authentication mode',
          )
        }
        // In order to use a Cognito user pool issued ID token for
        // authentication, we have to pretend that we are using
        // a custom Lambda authentication provider. Otherwise,
        // Amplify SDK attempts to sign into Cognito user pool
        // or perform FSSO to OIDC provider. We have tried to use
        // a generic GraphQL endpoint with OIDC authentication type
        // but that breaks subscriptions as AppSync's subscription
        // implementation is proprietary.
        this.amplify.configure({
          API: {
            GraphQL: {
              region: options.region,
              endpoint: options.graphqlUrl,
              defaultAuthMode: 'lambda',
            },
          },
        })
        break
      case GraphQLClientAuthMode.ApiKey:
        if (!options.apiKey) {
          throw new Error(
            'apiKey must be provided when using API_KEY authentication mode',
          )
        }
        this.amplify.configure({
          API: {
            GraphQL: {
              region: options.region,
              endpoint: options.graphqlUrl,
              defaultAuthMode: this.transformAuthMode(authModeToUse),
              apiKey: options.apiKey,
            },
          },
        })
        break
      case GraphQLClientAuthMode.IAM:
        this.amplify.configure(
          {
            API: {
              GraphQL: {
                region: options.region,
                endpoint: options.graphqlUrl,
                defaultAuthMode: this.transformAuthMode(authModeToUse),
              },
            },
          },
          {
            Auth: {
              credentialsProvider: new IAMCredentialsProvider(
                options.credentials,
              ),
            },
          },
        )
        break
    }
  }

  /**
   * Performs GraphQL query operation.
   *
   * @param options query document, query variables and authentication
   * token (optional). If authentication token is provided then the
   * token provided via the constructor will be ignored.
   * @returns query result.
   */
  public async query<T>(options: {
    query: string | DocumentNode
    variables?: any
    authToken?: string
  }): Promise<GraphQLResult<T>> {
    const authOptions = await this.resolveAuthOptions(options.authToken)
    try {
      return (await this.client.graphql<T>({
        query: options.query,
        variables: options.variables,
        ...authOptions,
      })) as GraphQLResult<T>
    } catch (err: any) {
      throw err.errors?.pop() ?? err
    }
  }

  /**
   * Performs GraphQL mutation operation.
   *
   * @param options mutation document, mutation variables and authentication
   * token (optional). If authentication token is provided then the
   * token provided via the constructor will be ignored.
   * @returns mutation result.
   */
  public async mutate<T>(options: {
    mutation: string | DocumentNode
    variables?: any
    authToken?: string
  }): Promise<GraphQLResult<T>> {
    const authOptions = await this.resolveAuthOptions(options.authToken)

    try {
      return (await this.client.graphql<T>({
        query: options.mutation,
        variables: options.variables,
        ...authOptions,
      })) as GraphQLResult<T>
    } catch (err: any) {
      throw err.errors?.pop() ?? err
    }
  }

  /**
   * Performs GraphQL subscription operation.
   *
   * @param options subscription document, subscription variables and
   * authentication token (optional). If authentication token is provided
   * then the token provided via the constructor will be ignored.
   * @returns observable for receiving subscription notifications.
   */
  public async subscribe<T>(options: {
    subscription: string | DocumentNode
    variables?: any
    authToken?: string
  }): Promise<Observable<GraphQLResult<T>>> {
    if (this.options.authMode === GraphQLClientAuthMode.IAM) {
      throw new Error(
        'Subscriptions are not supported with IAM authentication mode',
      )
    }

    try {
      const authOptions = await this.resolveAuthOptions(options.authToken)

      const result = this.client.graphql<T>({
        query: options.subscription,
        variables: options.variables,
        ...authOptions,
      })
      return result as unknown as Observable<GraphQLResult<T>>
    } catch (err: any) {
      throw err.errors?.pop() ?? err
    }
  }

  /**
   * Resolves a TokenProvider into its actual token value.
   * Handles both string tokens and async/sync function providers.
   */
  private async resolveToken(tokenProvider: TokenProvider): Promise<string> {
    if (typeof tokenProvider === 'string') {
      return tokenProvider
    }

    // tokenProvider is a function, call it and await the result
    return tokenProvider()
  }

  private transformAuthMode(input: GraphQLClientAuthMode): GraphQLAuthMode {
    switch (input) {
      case GraphQLClientAuthMode.OpenIDConnect:
        return GraphQLAuthMode.OpenIDConnect
      case GraphQLClientAuthMode.IAM:
        return GraphQLAuthMode.IAM
      case GraphQLClientAuthMode.ApiKey:
        return GraphQLAuthMode.ApiKey
    }
  }

  private async resolveAuthOptions(token?: string) {
    if (
      this.options.tokenProvider &&
      (this.options.authMode ??
        GraphQLClientAuthMode.OpenIDConnect ===
          GraphQLClientAuthMode.OpenIDConnect)
    ) {
      return {
        authToken:
          token ?? (await this.resolveToken(this.options.tokenProvider)),
      }
    }
    if (this.options.authMode == GraphQLClientAuthMode.ApiKey && token) {
      return {
        apiKey: token,
      }
    }
    return {}
  }
}
