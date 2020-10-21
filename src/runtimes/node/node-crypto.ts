import { generateKeyPair } from 'crypto'
import * as uuid from 'uuid'
import { promisify } from 'util'
import { CryptoProvider } from '../../core/crypto'

const generateKeyPairAsync = generateKeyPair && promisify(generateKeyPair)

export interface NodeKeyPair {
  publicKey: string
  privateKey: string
}

export const cryptoProvider: CryptoProvider = {
  generateKeyPair: async () => {
    const keyPair = await generateKeyPairAsync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    })

    return {
      id: uuid.v4(),
      ...keyPair,
    }
  },

  exportPublicKey: async (keyPair: NodeKeyPair) => {
    const publicKeyData = keyPair.publicKey
      .replace(/\n/g, '')
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A', '')

    return {
      symmetricAlgorithm: 'AES/256',
      algorithm: 'RSA',
      data: publicKeyData,
    }
  },

  exportSigningKey: async (keyPair: NodeKeyPair) => {
    return keyPair.privateKey
  },

  exportKeyPair: async (keyPair: NodeKeyPair): Promise<string> => {
    return JSON.stringify(keyPair)
  },

  importKeyPair: async (data: string): Promise<NodeKeyPair> => {
    return JSON.parse(data)
  },
}
