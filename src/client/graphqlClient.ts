import { GraphQLResult } from '@aws-amplify/api-graphql'
import { DocumentNode } from 'graphql'
import Observable from 'zen-observable'

export enum GraphQLClientAuthMode {
  OpenIDConnect = 'OPENID_CONNECT',
  IAM = 'AWS_IAM',
  ApiKey = 'API_KEY',
}

export type TokenProvider = (() => string | Promise<string>) | string

export type IAMCredentials = {
  accessKeyId: string
  secretAccessKey: string
  sessionToken?: string
}

export interface GraphQLClientOptions {
  /**
   * GraphQL URL i.e. AppSync URL in most cases.
   */
  graphqlUrl: string
  /**
   * AWS Region to connect to.
   */
  region: string

  /**
   * Authentication mode. If not provided, defaults to OPENID_CONNECT - the usual client mode
   */
  authMode?: GraphQLClientAuthMode

  /**
   * A provider which resolves to the ID token for authentication.
   */
  tokenProvider?: TokenProvider

  /**
   * If authMode is API_KEY, this is the API key to use for authentication.
   */
  apiKey?: string

  /**
   * if authMode is IAM, override default credential values with these.
   */
  credentials?: IAMCredentials
}

/**
 * Interface for GraphQL client operations.
 */
export interface GraphQLClient {
  /**
   * Performs GraphQL query operation.
   *
   * @param options query document, query variables and authentication
   * token (optional). If authentication token is provided then the
   * token provided via the constructor will be ignored.
   * @returns query result.
   */
  query<T>(options: {
    query: string | DocumentNode
    variables?: any
    idToken?: string
  }): Promise<GraphQLResult<T>>

  /**
   * Performs GraphQL mutation operation.
   *
   * @param options mutation document, mutation variables and authentication
   * token (optional). If authentication token is provided then the
   * token provided via the constructor will be ignored.
   * @returns mutation result.
   */
  mutate<T>(options: {
    mutation: string | DocumentNode
    variables?: any
    idToken?: string
  }): Promise<GraphQLResult<T>>

  /**
   * Performs GraphQL subscription operation.
   *
   * @param options subscription document, subscription variables and
   * authentication token (optional). If authentication token is provided
   * then the token provided via the constructor will be ignored.
   * @returns observable for receiving subscription notifications.
   */
  subscribe<T>(options: {
    subscription: string | DocumentNode
    variables?: any
    idToken?: string
  }): Promise<Observable<GraphQLResult<T>>>
}
