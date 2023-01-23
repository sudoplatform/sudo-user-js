export function parseToken(token: string): any {
  let parsed

  try {
    const object = JSON.parse(token)
    if (object && typeof object === 'object') {
      parsed = object
    }
  } catch (err) {}

  return parsed
}
