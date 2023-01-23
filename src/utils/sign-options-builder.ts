import * as jws from 'jws'
import { v4 } from 'uuid'

export function getSignOptions({
  aud,
  sub,
  iss,
  keyId,
  privateKey,
  attributes,
}: {
  aud: string
  sub: string
  iss: string
  keyId: string
  privateKey: string
  attributes?: Record<string, any>
}): jws.SignOptions {
  const now = Math.floor(Date.now() / 1000)
  const signOptions: jws.SignOptions = {
    header: { alg: 'RS256', kid: keyId },
    payload: {
      aud,
      sub,
      iss,
      jti: v4(),
      exp: now + 60,
      iat: now,
      nbf: now,
    },
    privateKey,
    encoding: 'utf8',
  }

  if (attributes) {
    for (const [key, value] of Object.entries(attributes)) {
      signOptions.payload[key] = value
    }
  }

  return signOptions
}
