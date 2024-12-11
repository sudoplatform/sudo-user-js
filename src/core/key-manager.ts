/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  DecodeError,
  KeyNotFoundError,
  PublicKeyFormat,
  SudoKeyManager,
} from '@sudoplatform/sudo-common'
import * as uuid from 'uuid'
import * as jws from 'jws'
import { cryptoProvider } from '../runtimes/node/node-crypto'

export interface PublicKey {
  keyId: string
  algorithm: string
  symmetricAlgorithm: string
  publicKey: string
  keyFormat: PublicKeyFormat
}

export interface KeyPair {
  publicKey: unknown
  publicKeyFormat: PublicKeyFormat
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
export class DefaultKeyManager implements KeyManager {
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
      new TextEncoder().encode(value).buffer,
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
      const error = err as Error
      throw new DecodeError(error.message)
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

    const jwt = jws.sign({
      header: { alg: 'RS256', kid: keyId },
      payload,
      privateKey: signingKey,
      encoding: 'utf8',
    })

    return jwt
  }

  /**
   * Exports public key in a format for use with SudoPlatform
   */
  public async exportPublicKey(keyId: string): Promise<PublicKey> {
    const publicKey = await this.sudoKeyManager.getPublicKey(keyId)
    if (!publicKey) {
      throw new Error('Invalid key ID for exportPublicKey')
    }
    const base64encoded = cryptoProvider.arrayBufferToBase64(publicKey.keyData)

    return {
      keyId,
      algorithm: DefaultKeyManager.Constants.publicKeyAlgorithm,
      symmetricAlgorithm: DefaultKeyManager.Constants.symmetricAlgorithm,
      publicKey: base64encoded,
      keyFormat: publicKey.keyFormat,
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
      publicKey: cryptoProvider.arrayBufferToBase64(publicKey.keyData),
      publicKeyFormat: publicKey.keyFormat,
      privateKey: cryptoProvider.arrayBufferToBase64(privateKey as ArrayBuffer),
    }
  }
}
