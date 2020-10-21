import { CryptoProvider } from '../../core/crypto'
import { arrayBufferToBase64, base64ToArrayBuffer } from '../../utils/binary'

export const cryptoProvider: CryptoProvider = {
  generateKeyPair: async (): Promise<CryptoKeyPair> => {
    return await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: 'SHA-256' },
      },
      true,
      ['encrypt', 'decrypt'],
    )
  },

  exportPublicKey: async (keyPair: CryptoKeyPair) => {
    const key = await crypto.subtle.exportKey('spki', keyPair.publicKey)
    const keyString = arrayBufferToBase64(key)

    return {
      symmetricAlgorithm: 'AES/256',
      algorithm: 'RSA',
      data: keyString.replace('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A', ''),
    }
  },

  exportSigningKey: async (keyPair: CryptoKeyPair) => {
    const keyBits = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
    const pkStr =
      '-----BEGIN PRIVATE KEY-----\n' +
      arrayBufferToBase64(keyBits) +
      '\n-----END PRIVATE KEY-----\n'
    return pkStr
  },

  exportKeyPair: async (keyPair: CryptoKeyPair): Promise<string> => {
    const privateKeyBits = await crypto.subtle.exportKey(
      'pkcs8',
      keyPair.privateKey,
    )
    const publicKeyBits = await crypto.subtle.exportKey(
      'spki',
      keyPair.publicKey,
    )

    return JSON.stringify({
      privateKey: arrayBufferToBase64(privateKeyBits),
      publicKey: arrayBufferToBase64(publicKeyBits),
    })
  },

  importKeyPair: async (data: string): Promise<CryptoKeyPair> => {
    const json = JSON.parse(data)

    return {
      publicKey: await crypto.subtle.importKey(
        'spki',
        base64ToArrayBuffer(json.publicKey),
        {
          name: 'RSA-OAEP',
          hash: { name: 'SHA-256' },
        },
        true,
        ['encrypt'],
      ),
      privateKey: await crypto.subtle.importKey(
        'pkcs8',
        base64ToArrayBuffer(json.privateKey),
        {
          name: 'RSA-OAEP',
          hash: { name: 'SHA-256' },
        },
        true,
        ['decrypt'],
      ),
    }
  },
}
