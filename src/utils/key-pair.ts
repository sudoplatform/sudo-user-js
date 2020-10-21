export interface KeyPairKey {
  provider: string
  type: string
  kid: string
}

export interface PublicKey {
  publicKey: string
}

export interface PrivateKey {
  privateKey: string
}

export type KeyPair = PublicKey & PrivateKey

export interface KeyPairStore {
  create(key: KeyPairKey, expiry?: Date): Promise<KeyPair>
  delete(key: KeyPairKey): Promise<void>

  getKeyPair(key: KeyPairKey): Promise<KeyPair | undefined>
  getKeyPairs(key: Omit<KeyPairKey, 'kid'>): Promise<(KeyPairKey & KeyPair)[]>
  getPrivateKey(key: KeyPairKey): Promise<PrivateKey | undefined>
  getPrivateKeys(
    key: Omit<KeyPairKey, 'kid'>,
  ): Promise<(KeyPairKey & PrivateKey)[]>
  getPublicKey(key: KeyPairKey): Promise<PublicKey | undefined>
  getPublicKeys(
    key: Omit<KeyPairKey, 'kid'>,
  ): Promise<(KeyPairKey & PublicKey)[]>
}
