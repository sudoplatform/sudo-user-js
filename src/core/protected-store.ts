export interface ProtectedStore {
  put(key: string, value: ArrayBuffer): Promise<void>
  get(key: string): Promise<ArrayBuffer>
  delete(key: string): Promise<void>
}
