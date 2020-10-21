export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let data = ''
  const bytes = new Uint8Array(buffer)
  const len = bytes.byteLength
  for (let i = 0; i < len; i++) {
    data += String.fromCharCode(bytes[i])
  }
  return window.btoa(data)
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = window.atob(base64)
  const len = binary.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}
