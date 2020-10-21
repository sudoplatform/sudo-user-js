import JWT from 'jsonwebtoken'
import * as uuid from 'uuid'
import { KeyPair } from './crypto'
import { cryptoProvider } from '../runtimes/node/node-crypto'

type Secret =
  | {
      type: 'string'
      value: string
    }
  | {
      type: 'keyPair'
      value: KeyPair
    }
  | {
      type: 'key'
      value: unknown
    }

export interface PublicKey {
  keyId: string
  algorithm: string
  symmetricAlgorithm: string
  publicKey: string
}

export interface KeyManager {
  addString(keyId: string, value: string): Promise<void>
  getString(keyId: string): Promise<string | undefined>
  generateKeyPair(keyId?: string): Promise<string>
  exportPublicKey(keyId: string): Promise<PublicKey>
  signJWT(keyId: string, payload: Record<string, unknown>): Promise<string>
  reset(): Promise<void>
  removeItem(keyId: string): Promise<void>
}

/**
 * Key Manager
 */
export class KeyManager {
  /** Do not expose these directly */
  #secrets: Record<string, Secret> = {}

  /** Adds a secret into private _secrets object */
  private async addSecret(id: string, secret: Secret): Promise<void> {
    this.#secrets[id] = secret
  }

  /**
   * Adds a string value into key manager
   */
  public async addString(keyId: string, value: string): Promise<void> {
    await this.addSecret(keyId, { type: 'string', value })
  }

  /**
   * Returns a string value from key manager
   */
  public async getString(keyId: string): Promise<string | undefined> {
    const secret = this.#secrets[keyId]
    if (secret) {
      if (secret?.type !== 'string') {
        throw new Error(`NOT_FOUND: No string for ${keyId}`)
      }
      return secret.value
    }
  }

  /**
   * Generates and adds a new key pair into key manager
   * @returns Key ID
   */
  public async generateKeyPair(keyId = uuid.v4()): Promise<string> {
    const keyPair = await cryptoProvider.generateKeyPair()
    await this.addSecret(keyId, { type: 'keyPair', value: keyPair })
    return keyId
  }

  /**
   * Removes a secret
   */
  public async removeItem(id: string): Promise<void> {
    delete this.#secrets[id]
  }

  /**
   * Signs a JWT with a signing key that is in key manager
   * @returns JWT data
   */
  public async signJWT(
    keyId: string,
    payload: Record<string, unknown>,
  ): Promise<string> {
    const keyPair = this.#secrets[keyId]
    if (keyPair?.type !== 'keyPair') {
      throw new Error('Invalid key ID for signJWT')
    }

    const signingKey = await cryptoProvider.exportSigningKey(keyPair.value)
    return JWT.sign(payload, signingKey, {
      algorithm: 'RS256',
      keyid: keyId,
    })
  }

  /**
   * Exports public key in a format for use with SudoPlatform
   */
  public async exportPublicKey(keyId: string): Promise<PublicKey> {
    const keyPair = this.#secrets[keyId]
    if (keyPair?.type !== 'keyPair') {
      throw new Error('Invalid key ID for exportPublicKey')
    }

    const publicKey = await cryptoProvider.exportPublicKey(keyPair.value)

    return {
      keyId,
      algorithm: publicKey.algorithm,
      symmetricAlgorithm: publicKey.symmetricAlgorithm,
      publicKey: publicKey.data,
    }
  }

  /**
   * Clears all private keys from memory
   */
  public async reset(): Promise<void> {
    this.#secrets = {}
  }

  public async retrieveKeyPair(keyId: string): Promise<KeyPair> {
    const keyPair = this.#secrets[keyId]
    if (keyPair?.type !== 'keyPair') {
      throw new Error('Invalid key ID for exportPublicKey')
    }
    return keyPair.value
  }
}
