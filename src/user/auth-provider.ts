import { v4 } from 'uuid'
import * as jws from 'jws'
import { getSignOptions } from '../utils/sign-options-builder'
import { FatalError } from '@sudoplatform/sudo-common'
import { parseToken } from '../utils/parse-token'

export interface AuthenticationInfo {
  /**
   * Authentication type.
   */
  type: string
  /**
   * Indicates whether or not the authentication information is valid.
   *
   * @return *true* if the authentication information is valid.
   */
  isValid(): boolean
  /**
   * Encodes the authentication information as a string.
   *
   * @return encoded authentication information.
   */
  encode(): string
  /**
   * Returns the username associated with this authentication information.
   *
   * @return username.
   */
  getUsername(): string
}

/* Encapsulates an authentication provider responsible for generating
 * authentication information required to sign into the backend.
 */
export interface AuthenticationProvider {
  /**
   * Generates and returns authentication information.
   *
   * @return authentication information.
   */
  getAuthenticationInfo(): Promise<AuthenticationInfo>
  /**
   * Resets internal state and releases any associated resources.
   */
  reset(): void
}

/**
 * Authentication info consisting of a JWT signed using the TEST registration key.
 */
export class TESTAuthenticationInfo implements AuthenticationInfo {
  readonly type: string = 'TEST'

  constructor(private jwt: string) {}

  isValid(): boolean {
    return true
  }

  encode(): string {
    return this.jwt
  }

  getUsername(): string {
    const jwt: any = jws.decode(this.jwt)
    if (jwt.payload) {
      const payload = parseToken(jwt.payload)
      const sub = payload['sub']
      if (sub) {
        return sub
      } else {
        throw new FatalError('sub missing from TEST user JWT.')
      }
    } else {
      throw new FatalError('payload missing from TEST user JWT.')
    }
  }
}

/**
 * Authentication provider for generating authentication info using a TEST registration key.
 *
 * @param name provider name. This name will be prepended to the generated UUID in JWT sub.
 * @param privateKey PEM encoded RSA private key.
 * @param keyId key ID of the TEST registration key which is obtained from the admin console.
 * @param attributes additional attributes to be added to the issued authentication info.
 */
export class TESTAuthenticationProvider implements AuthenticationProvider {
  readonly testRegistrationIssuer: string = 'testRegisterIssuer'
  readonly testRegistrationAudience: string = 'testRegisterAudience'
  constructor(
    private name: string,
    private privateKey: string,
    private keyId: string = 'register_key',
    private attributes?: Record<string, any>,
  ) {}

  async getAuthenticationInfo(): Promise<AuthenticationInfo> {
    const signOptions = getSignOptions({
      aud: this.testRegistrationAudience,
      sub: `${this.name}-${v4()}`,
      iss: this.testRegistrationIssuer,
      keyId: this.keyId,
      privateKey: this.privateKey,
      attributes: this.attributes,
    })

    const jwt = jws.sign(signOptions)

    return new TESTAuthenticationInfo(jwt)
  }

  reset(): void {
    // Not implemented
  }
}

/**
 * Authentication info consisting of a JWT signed using the locally stored private key.
 */
export class LocalAuthenticationInfo implements AuthenticationInfo {
  readonly type: string = 'FSSO'

  constructor(private jwt: string, private username: string) {}

  isValid(): boolean {
    return true
  }

  encode(): string {
    return this.jwt
  }

  getUsername(): string {
    return this.username
  }
}

/**
 * Authentication info consisting of a JWT signed using the locally stored private key.
 *
 * @param name provider name. This name will be used to populate JWT iss (issuer).
 * @param privateKey PEM encoded RSA private key.
 * @param keyId key ID.
 * @param username username to be associated with the issued authentication info.
 * @param attributes additional attributes to be added to the issued authentication info.
 */
export class LocalAuthenticationProvider implements AuthenticationProvider {
  constructor(
    private name: string,
    private privateKey: string,
    private keyId: string,
    private username: string,
    private attributes?: Record<string, any>,
  ) {}

  async getAuthenticationInfo(): Promise<AuthenticationInfo> {
    const signOptions = getSignOptions({
      aud: 'identity-service',
      sub: this.username,
      iss: this.name,
      keyId: this.keyId,
      privateKey: this.privateKey,
      attributes: this.attributes,
    })

    const jwt = jws.sign(signOptions)

    return new LocalAuthenticationInfo(jwt, this.username)
  }

  reset(): void {
    // Not implemented
  }
}
