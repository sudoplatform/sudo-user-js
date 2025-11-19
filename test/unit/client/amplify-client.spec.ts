import { AmplifyClient } from '../../../src/client/amplifyClient'
import {
  GraphQLClientAuthMode,
  GraphQLClientOptions,
  IAMCredentials,
  TokenProvider,
} from '../../../src/client/graphqlClient'
import { DocumentNode, Kind } from 'graphql'
import Observable from 'zen-observable'

import {
  mock,
  instance,
  reset,
  verify,
  anything,
  capture,
  when,
} from 'ts-mockito'

// Spy on the AmplifyClassV6 constructor to return our mocked nstance
const amplifyConstructorSpy = jest
  .spyOn(require('@aws-amplify/core'), 'AmplifyClassV6')
  .mockImplementation(() => instance(amplifyClassV6Mock))

const generateClientSpy = jest
  .spyOn(require('@aws-amplify/api-graphql/internals'), 'generateClient')
  .mockImplementation(() => instance(v6ClientMock))

import { AmplifyClassV6 } from '@aws-amplify/core'
import { GraphQLResult, V6Client } from '@aws-amplify/api-graphql'
// Mock environment variables for IAM auth
const originalEnv = process.env

const mockGraphQLResult: GraphQLResult<any> = {
  data: { test: 'result' },
  errors: undefined,
  extensions: undefined,
}

const mockGraphQLError = {
  message: 'Test GraphQL error',
  locations: [],
  path: [],
}

const testOptions: GraphQLClientOptions = {
  graphqlUrl: 'https://test.appsync-api.us-east-1.amazonaws.com/graphql',
  region: 'us-east-1',
}

const testIAMCredentials: IAMCredentials = {
  accessKeyId: 'test-access-key',
  secretAccessKey: 'test-secret-key',
  sessionToken: 'test-session-token',
}

const testTokenProvider: TokenProvider = 'test-token'

const testAsyncTokenProvider: TokenProvider = async (): Promise<string> => {
  return 'async-test-token'
}

const testQuery = `
  query GetUser($id: ID!) {
    getUser(id: $id) {
      id
      name
    }
  }
`

const testMutation = `
  mutation CreateUser($input: CreateUserInput!) {
    createUser(input: $input) {
      id
      name
    }
  }
`

const testSubscription = `
  subscription OnUserCreated {
    onUserCreated {
      id
      name
    }
  }
`

const testVariables = {
  id: 'test-user-id',
}
const amplifyClassV6Mock = mock<AmplifyClassV6>()
const v6ClientMock = mock<V6Client>()

describe('AmplifyClient', () => {
  beforeEach(() => {
    jest.resetModules()
    jest.clearAllMocks()
    process.env = { ...originalEnv }
  })

  afterEach(() => {
    process.env = originalEnv
    jest.clearAllMocks()
    reset(amplifyClassV6Mock)
    reset(v6ClientMock)
  })

  describe('constructor', () => {
    it('should create instance with OpenIDConnect auth mode and token provider', () => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      }

      const client = new AmplifyClient(options)
      expect(client).toBeInstanceOf(AmplifyClient)
    })

    it('should create instance with ApiKey auth mode', () => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.ApiKey,
        apiKey: 'test-api-key',
      }

      const client = new AmplifyClient(options)
      expect(client).toBeInstanceOf(AmplifyClient)
    })

    it('should create instance with IAM auth mode and credentials', () => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.IAM,
        credentials: testIAMCredentials,
      }

      const client = new AmplifyClient(options)
      expect(client).toBeInstanceOf(AmplifyClient)
    })

    it('should create instance with IAM auth mode using environment variables', () => {
      process.env.AWS_ACCESS_KEY_ID = 'env-access-key'
      process.env.AWS_SECRET_ACCESS_KEY = 'env-secret-key'
      process.env.AWS_SESSION_TOKEN = 'env-session-token'

      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.IAM,
      }

      const client = new AmplifyClient(options)
      expect(client).toBeInstanceOf(AmplifyClient)
    })

    it('should throw error when OpenIDConnect auth mode is used without token provider', () => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
      }

      expect(() => new AmplifyClient(options)).toThrowError(
        'tokenProvider must be provided when using OPENID_CONNECT authentication mode',
      )
    })

    it('should throw error when ApiKey auth mode is used without api key', () => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.ApiKey,
      }

      expect(() => new AmplifyClient(options)).toThrowError(
        'apiKey must be provided when using API_KEY authentication mode',
      )
    })

    it('should default to OpenIDConnect auth mode when no auth mode is specified', () => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        tokenProvider: testTokenProvider,
      }

      const client = new AmplifyClient(options)
      expect(client).toBeInstanceOf(AmplifyClient)
    })
  })

  describe('IAMCredentialsProvider', () => {
    it('should configure amplify with IAM credentials provider', () => {
      process.env.AWS_ACCESS_KEY_ID = 'env-access-key'
      process.env.AWS_SECRET_ACCESS_KEY = 'env-secret-key'

      new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.IAM,
      })

      // Verify that configure was called with both config and credentials provider
      verify(amplifyClassV6Mock.configure(anything(), anything())).once()

      // Capture the configure method arguments
      const actualConfigArgs = capture(amplifyClassV6Mock.configure).first()
      const [configArg, credentialsArg] = actualConfigArgs

      // Verify the configuration matches expected values
      expect(configArg).toEqual({
        API: {
          GraphQL: {
            region: testOptions.region,
            endpoint: testOptions.graphqlUrl,
            defaultAuthMode: 'iam',
          },
        },
      })

      // Verify credentials provider is present
      expect(credentialsArg).toEqual({
        Auth: {
          credentialsProvider: expect.any(Object),
        },
      })
    })
  })

  describe('query', () => {
    let client: AmplifyClient

    beforeEach(() => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      }
      client = new AmplifyClient(options)
    })

    it('should perform GraphQL query successfully', async () => {
      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const result = await client.query({
        query: testQuery,
        variables: testVariables,
      })

      expect(result).toEqual(mockGraphQLResult)
      verify(v6ClientMock.graphql(anything())).once()

      const [actualQueryParams] = capture((v6ClientMock as any).graphql).first()
      expect(actualQueryParams).toMatchObject({
        query: testQuery,
        variables: testVariables,
        authToken: 'test-token',
      })
    })

    it('should perform GraphQL query with custom auth token', async () => {
      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const customToken = 'custom-token'
      const result = await client.query({
        query: testQuery,
        variables: testVariables,
        authToken: customToken,
      })

      expect(result).toEqual(mockGraphQLResult)
      verify(v6ClientMock.graphql(anything())).once()

      const [actualQueryParams] = capture((v6ClientMock as any).graphql).first()
      expect(actualQueryParams).toMatchObject({
        query: testQuery,
        variables: testVariables,
        authToken: customToken,
      })
    })

    it('should handle GraphQL errors', async () => {
      const mockError = {
        errors: [mockGraphQLError],
      }
      when(v6ClientMock.graphql(anything())).thenReject(mockError as any)

      await expect(
        client.query({
          query: testQuery,
          variables: testVariables,
        }),
      ).rejects.toEqual(mockGraphQLError)
    })

    it('should handle non-GraphQL errors', async () => {
      const mockError = new Error('Network error')
      when(v6ClientMock.graphql(anything())).thenReject(mockError as any)

      await expect(
        client.query({
          query: testQuery,
          variables: testVariables,
        }),
      ).rejects.toEqual(mockError)
    })

    it('should resolve async token provider', async () => {
      const optionsWithAsyncProvider: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testAsyncTokenProvider,
      }
      const clientWithAsyncProvider = new AmplifyClient(
        optionsWithAsyncProvider,
      )

      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      await clientWithAsyncProvider.query({
        query: testQuery,
        variables: testVariables,
      })

      const [actualQueryParams] = capture((v6ClientMock as any).graphql).first()
      expect(actualQueryParams).toMatchObject({
        query: testQuery,
        variables: testVariables,
        authToken: 'async-test-token',
      })
    })
  })

  describe('mutate', () => {
    let client: AmplifyClient

    beforeEach(() => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      }
      client = new AmplifyClient(options)
    })

    it('should perform GraphQL mutation successfully', async () => {
      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const result = await client.mutate({
        mutation: testMutation,
        variables: testVariables,
      })

      expect(result).toEqual(mockGraphQLResult)

      const [actualMutateParams] = capture(
        (v6ClientMock as any).graphql,
      ).first()
      expect(actualMutateParams).toMatchObject({
        query: testMutation,
        variables: testVariables,
        authToken: 'test-token',
      })
    })

    it('should perform GraphQL mutation with custom auth token', async () => {
      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const customToken = 'custom-token'
      const result = await client.mutate({
        mutation: testMutation,
        variables: testVariables,
        authToken: customToken,
      })

      expect(result).toEqual(mockGraphQLResult)
      const [actualMutateParams] = capture(
        (v6ClientMock as any).graphql,
      ).first()
      expect(actualMutateParams).toMatchObject({
        query: testMutation,
        variables: testVariables,
        authToken: customToken,
      })
    })

    it('should handle GraphQL mutation errors', async () => {
      const mockError = {
        errors: [mockGraphQLError],
      }
      when(v6ClientMock.graphql(anything())).thenReject(mockError as any)

      await expect(
        client.mutate({
          mutation: testMutation,
          variables: testVariables,
        }),
      ).rejects.toEqual(mockGraphQLError)
    })
  })

  describe('subscribe', () => {
    let client: AmplifyClient

    beforeEach(() => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      }
      client = new AmplifyClient(options)
    })

    it('should perform GraphQL subscription successfully', async () => {
      const mockObservable = new Observable<GraphQLResult<any>>((observer) => {
        observer.next(mockGraphQLResult)
        observer.complete()
      })

      when(v6ClientMock.graphql(anything())).thenResolve(mockObservable as any)

      const result = await client.subscribe({
        subscription: testSubscription,
        variables: testVariables,
      })

      expect(result).toBe(mockObservable)
      const [actualSubscribeParams] = capture(
        (v6ClientMock as any).graphql,
      ).first()
      expect(actualSubscribeParams).toMatchObject({
        query: testSubscription,
        variables: testVariables,
        authToken: 'test-token',
      })
    })

    it('should throw error when using IAM auth mode for subscriptions', async () => {
      const iamClient = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.IAM,
        credentials: testIAMCredentials,
      })

      await expect(
        iamClient.subscribe({
          subscription: testSubscription,
        }),
      ).rejects.toThrowError(
        'Subscriptions are not supported with IAM authentication mode',
      )
    })

    it('should handle subscription errors', async () => {
      const mockError = {
        errors: [mockGraphQLError],
      }
      when(v6ClientMock.graphql(anything())).thenThrow(mockError as any)

      await expect(
        client.subscribe({
          subscription: testSubscription,
          variables: testVariables,
        }),
      ).rejects.toEqual(mockGraphQLError)
    })
  })

  describe('ApiKey auth mode', () => {
    let client: AmplifyClient

    beforeEach(() => {
      const options: GraphQLClientOptions = {
        ...testOptions,
        authMode: GraphQLClientAuthMode.ApiKey,
        apiKey: 'test-api-key',
      }
      client = new AmplifyClient(options)
    })

    it('should perform query with API key auth', async () => {
      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const result = await client.query({
        query: testQuery,
        variables: testVariables,
      })

      expect(result).toEqual(mockGraphQLResult)
      const [actualQueryParams] = capture((v6ClientMock as any).graphql).first()
      expect(actualQueryParams).toMatchObject({
        query: testQuery,
        variables: testVariables,
      })
    })

    it('should use custom API key when provided in auth token', async () => {
      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const customApiKey = 'custom-api-key'
      const result = await client.query({
        query: testQuery,
        variables: testVariables,
        authToken: customApiKey,
      })

      expect(result).toEqual(mockGraphQLResult)
      const [actualQueryParams] = capture((v6ClientMock as any).graphql).first()
      expect(actualQueryParams).toMatchObject({
        query: testQuery,
        variables: testVariables,
        apiKey: customApiKey,
      })
    })
  })

  describe('IAM auth mode', () => {
    beforeEach(() => {
      process.env.AWS_ACCESS_KEY_ID = 'env-access-key'
      process.env.AWS_SECRET_ACCESS_KEY = 'env-secret-key'
      process.env.AWS_SESSION_TOKEN = 'env-session-token'
    })

    it('should perform query with IAM auth using environment variables', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.IAM,
      })

      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const result = await client.query({
        query: testQuery,
        variables: testVariables,
      })

      expect(result).toEqual(mockGraphQLResult)
      const [actualQueryParams] = capture((v6ClientMock as any).graphql).first()
      expect(actualQueryParams).toMatchObject({
        query: testQuery,
        variables: testVariables,
      })
    })

    it('should perform query with IAM auth using provided credentials', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.IAM,
        credentials: testIAMCredentials,
      })

      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const result = await client.query({
        query: testQuery,
        variables: testVariables,
      })

      expect(result).toEqual(mockGraphQLResult)
      const [actualQueryParams] = capture((v6ClientMock as any).graphql).first()
      expect(actualQueryParams).toMatchObject({
        query: testQuery,
        variables: testVariables,
      })
    })
  })

  describe('Token resolution', () => {
    it('should resolve string token provider', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: 'string-token',
      })

      const resolveToken = (client as any).resolveToken.bind(client)
      const result = await resolveToken('string-token')

      expect(result).toBe('string-token')
    })

    it('should resolve function token provider', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      })

      const resolveToken = (client as any).resolveToken.bind(client)
      const result = await resolveToken(() => 'function-token')

      expect(result).toBe('function-token')
    })

    it('should resolve async function token provider', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      })

      const resolveToken = (client as any).resolveToken.bind(client)
      const result = await resolveToken(async () => 'async-function-token')

      expect(result).toBe('async-function-token')
    })
  })

  describe('Auth mode transformation', () => {
    it('should transform GraphQLClientAuthMode to internal GraphQLAuthMode', () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      })

      const transformAuthMode = (client as any).transformAuthMode.bind(client)

      expect(transformAuthMode(GraphQLClientAuthMode.OpenIDConnect)).toBe(
        'oidc',
      )
      expect(transformAuthMode(GraphQLClientAuthMode.IAM)).toBe('iam')
      expect(transformAuthMode(GraphQLClientAuthMode.ApiKey)).toBe('apiKey')
    })
  })

  describe('resolveAuthOptions', () => {
    it('should return authToken for OpenIDConnect mode', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: 'test-token',
      })

      const resolveAuthOptions = (client as any).resolveAuthOptions.bind(client)
      const result = await resolveAuthOptions()

      expect(result).toEqual({ authToken: 'test-token' })
    })

    it('should return custom authToken when provided for OpenIDConnect mode', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: 'default-token',
      })

      const resolveAuthOptions = (client as any).resolveAuthOptions.bind(client)
      const result = await resolveAuthOptions('custom-token')

      expect(result).toEqual({ authToken: 'custom-token' })
    })

    it('should return apiKey for ApiKey mode when token provided', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.ApiKey,
        apiKey: 'default-api-key',
      })

      const resolveAuthOptions = (client as any).resolveAuthOptions.bind(client)
      const result = await resolveAuthOptions('custom-api-key')

      expect(result).toEqual({ apiKey: 'custom-api-key' })
    })

    it('should return empty object for IAM mode', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.IAM,
        credentials: testIAMCredentials,
      })

      const resolveAuthOptions = (client as any).resolveAuthOptions.bind(client)
      const result = await resolveAuthOptions()

      expect(result).toEqual({})
    })

    it('should return empty object for ApiKey mode without token', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.ApiKey,
        apiKey: 'default-api-key',
      })

      const resolveAuthOptions = (client as any).resolveAuthOptions.bind(client)
      const result = await resolveAuthOptions()

      expect(result).toEqual({})
    })
  })

  describe('Edge cases and error handling', () => {
    it('should handle undefined variables in query', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      })

      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const result = await client.query({
        query: testQuery,
      })

      expect(result).toEqual(mockGraphQLResult)
      const [actualQueryParams] = capture((v6ClientMock as any).graphql).first()
      expect(actualQueryParams).toMatchObject({
        query: testQuery,
        authToken: 'test-token',
      })
    })

    it('should handle DocumentNode as query type', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      })

      when(v6ClientMock.graphql(anything())).thenResolve(
        mockGraphQLResult as any,
      )

      const mockDocumentNode: DocumentNode = {
        kind: Kind.DOCUMENT,
        definitions: [],
      }

      const result = await client.query({
        query: mockDocumentNode,
        variables: testVariables,
      })

      expect(result).toEqual(mockGraphQLResult)
      const [actualQueryParams] = capture((v6ClientMock as any).graphql).first()
      expect(actualQueryParams).toMatchObject({
        query: mockDocumentNode,
        variables: testVariables,
        authToken: 'test-token',
      })
    })

    it('should configure amplify with correct parameters for OpenIDConnect', () => {
      new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      })

      // Verify that configure was called once
      verify(amplifyClassV6Mock.configure(anything())).once()

      // Capture the configure method arguments
      const capturedCalls = capture(amplifyClassV6Mock.configure).last()
      const [configArg] = capturedCalls

      // Verify the captured configuration matches expected values
      expect(configArg).toEqual({
        API: {
          GraphQL: {
            region: testOptions.region,
            endpoint: testOptions.graphqlUrl,
            defaultAuthMode: 'lambda',
          },
        },
      })
    })

    it('should configure amplify with correct parameters for ApiKey', () => {
      const apiKey = 'test-api-key'
      new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.ApiKey,
        apiKey,
      })

      // Verify that configure was called once
      verify(amplifyClassV6Mock.configure(anything())).once()

      // Capture the configure method arguments
      const capturedCalls = capture(amplifyClassV6Mock.configure).last()
      const [configArg] = capturedCalls

      // Verify the captured configuration matches expected values
      expect(configArg).toEqual({
        API: {
          GraphQL: {
            region: testOptions.region,
            endpoint: testOptions.graphqlUrl,
            defaultAuthMode: 'apiKey',
            apiKey,
          },
        },
      })
    })

    it('should handle errors with empty errors array', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      })

      const mockError = {
        errors: [],
      }
      when(v6ClientMock.graphql(anything())).thenReject(mockError as any)

      await expect(
        client.query({
          query: testQuery,
          variables: testVariables,
        }),
      ).rejects.toEqual(mockError)
    })

    it('should handle subscription error when not using IAM', async () => {
      const client = new AmplifyClient({
        ...testOptions,
        authMode: GraphQLClientAuthMode.OpenIDConnect,
        tokenProvider: testTokenProvider,
      })

      const mockError = new Error('Subscription failed')
      when(v6ClientMock.graphql(anything())).thenThrow(mockError as any)

      await expect(
        client.subscribe({
          subscription: testSubscription,
          variables: testVariables,
        }),
      ).rejects.toEqual(mockError)
    })
  })
})
