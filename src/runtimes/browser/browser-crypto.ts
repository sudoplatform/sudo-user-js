import { CryptoProvider } from '../../core/crypto'
import { Base64 } from '@sudoplatform/sudo-common'

export const cryptoProvider: CryptoProvider = {
  arrayBufferToBase64: (buffer: ArrayBuffer): string => {
    return Base64.encode(buffer)
  },
}
