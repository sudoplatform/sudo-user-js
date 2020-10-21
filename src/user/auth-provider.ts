import * as JWT from 'jsonwebtoken'
import { v4 } from 'uuid'

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
    return ''
  }
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
  getAuthenticationInfo(): AuthenticationInfo
  /**
   * Resets internal state and releases any associated resources.
   */
  reset(): void
}

/**
 * Authentication provider for generating authentication info using a TEST registration key.
 *
 * @param name provider name. This name will be prepended to the generated UUID in JWT sub.
 * @param privateKey PEM encoded RSA private key.
 * @param keyId key ID of the TEST registration key which is obtained from the admin console.
 */
export class TESTAuthenticationProvider implements AuthenticationProvider {
  readonly testRegistrationIssuer: string = 'testRegisterIssuer'
  readonly testRegistrationAudience: string = 'testRegisterAudience'
  constructor(
    private name: string,
    private privateKey: string,
    private keyId: string = 'register_key',
  ) {}

  getAuthenticationInfo(): AuthenticationInfo {
    const jwt = JWT.sign({}, this.privateKey, {
      jwtid: v4(),
      audience: this.testRegistrationAudience,
      expiresIn: '60s',
      notBefore: '0m',
      subject: `${this.name}-${v4()}`,
      issuer: this.testRegistrationIssuer,
      header: { alg: 'RS256', kid: this.keyId },
      algorithm: 'RS256',
    })
    return new TESTAuthenticationInfo(jwt)
  }

  reset(): void {
    // Not implemented
  }
}
