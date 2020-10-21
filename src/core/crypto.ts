export type PublicKey = {
  algorithm: 'RSA'
  symmetricAlgorithm: 'AES/256'
  data: string
}

export interface KeyPair {
  publicKey: unknown
  privateKey: unknown
}

export interface CryptoProvider {
  generateKeyPair(): Promise<KeyPair>
  exportPublicKey(keyPair: KeyPair): Promise<PublicKey>
  exportSigningKey(keyPair: KeyPair): Promise<string>
  exportKeyPair(keyPair: KeyPair): Promise<string>
  importKeyPair(data: string): Promise<KeyPair>
}
