import {
  DecodeError,
  KeyNotFoundError,
  SudoKeyManager,
} from '@sudoplatform/sudo-common'
import JWT from 'jsonwebtoken'
import * as uuid from 'uuid'
import { cryptoProvider } from '../runtimes/node/node-crypto'

export interface PublicKey {
  keyId: string
  algorithm: string
  symmetricAlgorithm: string
  publicKey: string
}

export interface KeyPair {
  publicKey: unknown
  privateKey: unknown
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
export class KeyManager implements KeyManager {
  private static Constants = {
    publicKeyAlgorithm: 'RSA',
    symmetricAlgorithm: 'AES/256',
  }

  constructor(private sudoKeyManager: SudoKeyManager) {}

  /**
   * Adds a string value into key manager
   */
  public async addString(keyId: string, value: string): Promise<void> {
    await this.sudoKeyManager.addPassword(
      new TextEncoder().encode(value),
      keyId,
    )
  }

  /**
   * Returns a string value from key manager
   */
  public async getString(keyId: string): Promise<string | undefined> {
    const passwordBuffer = await this.sudoKeyManager.getPassword(keyId)
    if (!passwordBuffer) {
      throw new KeyNotFoundError(`No key found for keyId: ${keyId}`)
    }
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(passwordBuffer)
    } catch (err) {
      throw new DecodeError(err.message)
    }
  }

  /**
   * Generates and adds a new key pair into key manager
   * @returns Key ID
   */
  public async generateKeyPair(keyId = uuid.v4()): Promise<string> {
    await this.sudoKeyManager.generateKeyPair(keyId)
    return keyId
  }

  /**
   * Removes a secret
   */
  public async removeItem(id: string): Promise<void> {
    await this.sudoKeyManager.deletePassword(id)
  }

  /**
   * Signs a JWT with a signing key that is in key manager
   * @returns JWT data
   */
  public async signJWT(
    keyId: string,
    payload: Record<string, unknown>,
  ): Promise<string> {
    const privateKeyBits = await this.sudoKeyManager.getPrivateKey(keyId)
    if (!privateKeyBits) {
      throw new KeyNotFoundError(`No key found for keyId: ${keyId}`)
    }

    const base64encoded = cryptoProvider.arrayBufferToBase64(privateKeyBits)

    //PEM encode private key
    const signingKey = `-----BEGIN PRIVATE KEY-----\n${base64encoded}\n-----END PRIVATE KEY-----`

    return JWT.sign(payload, signingKey, {
      algorithm: 'RS256',
      keyid: keyId,
    })
  }

  /**
   * Exports public key in a format for use with SudoPlatform
   */
  public async exportPublicKey(keyId: string): Promise<PublicKey> {
    const publicKeyBits = await this.sudoKeyManager.getPublicKey(keyId)
    if (!publicKeyBits) {
      throw new Error('Invalid key ID for exportPublicKey')
    }
    const base64encoded = cryptoProvider.arrayBufferToBase64(publicKeyBits)

    // The public key is PKCS#8 format(the ASN.1 structure of SubjectPublicKeyInfo).
    // The SudoPlatform expects PKCS#1 format.
    // The difference is that PKCS#8 contains the algorithm identifier.
    // The algorithm identifier for RSA encryption is `1.2.840.113549.1.1.1` and the Base64
    // version of this (for a key with a 2048 bit modulus) is `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A`
    // Therefore let's remove that from the public key.
    // Ref: https://stackoverflow.com/questions/8784905/command-line-tool-to-export-rsa-private-key-to-rsapublickey
    const pkcs1PublicKey = base64encoded.replace(
      'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A',
      '',
    )

    return {
      keyId,
      algorithm: KeyManager.Constants.publicKeyAlgorithm,
      symmetricAlgorithm: KeyManager.Constants.symmetricAlgorithm,
      publicKey: pkcs1PublicKey,
    }
  }

  /**
   * Clears all private keys from memory
   */
  public async reset(): Promise<void> {
    await this.sudoKeyManager.removeAllKeys()
  }

  public async retrieveKeyPair(keyId: string): Promise<KeyPair> {
    const publicKey = await this.sudoKeyManager.getPublicKey(keyId)
    if (!publicKey) {
      throw new KeyNotFoundError(`Public key not found for keyId: ${keyId}`)
    }
    const privateKey = await this.sudoKeyManager.getPrivateKey(keyId)
    if (!privateKey) {
      throw new KeyNotFoundError(`Private key not found for keyId: ${keyId}`)
    }

    return {
      publicKey: cryptoProvider.arrayBufferToBase64(publicKey as ArrayBuffer),
      privateKey: cryptoProvider.arrayBufferToBase64(privateKey as ArrayBuffer),
    }
  }
}
