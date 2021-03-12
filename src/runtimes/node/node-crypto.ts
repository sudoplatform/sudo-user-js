import { CryptoProvider } from '../../core/crypto'

export const cryptoProvider: CryptoProvider = {
  arrayBufferToBase64: (buffer: ArrayBuffer): string => {
    return Buffer.from(buffer).toString('base64')
  },
}
