import { Publisher } from './publisher'
import { Subscriber } from './subscriber'
import * as JWT from 'jsonwebtoken'

type Secret = {
  type: 'string'
  value: string
}

export interface Store {
  setItem(keyId: string, value: string): Promise<void>
  getItem(keyId: string): string | undefined
  removeItem(keyId: string): void
  reset(): void
}

/**
 * Stores authentication details such as tokens and username
 */
export class AuthenticationStore implements Store, Publisher {
  /** Do not expose these directly */
  // eslint-disable-next-line tree-shaking/no-side-effects-in-initialization
  #secrets: Record<string, Secret> = {}
  subscribers: Subscriber[] = []

  /** Adds a secret into private _secrets object */
  private async addSecret(keyId: string, secret: Secret): Promise<void> {
    const key = keyId.substr(keyId.lastIndexOf('.') + 1)
    this.#secrets[key] = secret
  }

  /**
   * Adds a string value into authentication store
   */
  public async setItem(keyId: string, value: string): Promise<void> {
    const key = keyId.substr(keyId.lastIndexOf('.') + 1)
    if (key === 'idToken') {
      // Store the token expiry
      const decoded: any = JWT.decode(value, { complete: true })
      if (decoded) {
        const tokenExpiry = decoded.payload['exp']
        await this.addSecret('tokenExpiry', {
          type: 'string',
          value: tokenExpiry,
        })
      }
    }
    await this.addSecret(key, { type: 'string', value })
    await this.notifySubscribers(key)
  }

  /**
   * Returns a string value from authentication store
   */
  public getItem(keyId: string): string | undefined {
    const key = keyId.substr(keyId.lastIndexOf('.') + 1)
    const secret = this.#secrets[key]
    return secret?.type === 'string' ? secret.value : undefined
  }

  /**
   * Removes a secret
   */
  public removeItem(keyId: string): void {
    const key = keyId.substr(keyId.lastIndexOf('.') + 1)
    delete this.#secrets[key]
  }

  /**
   * Clears all secrets
   */
  public reset(): void {
    this.#secrets = {}
  }

  /**
   * Register a subscriber to be notified when items are added
   *
   * @param subscriber a subscriber to be notified when items are added
   */
  public async subscribe(subscriber: Subscriber): Promise<void> {
    this.subscribers.push(subscriber)
  }

  /**
   * Remove a subscriber from the list of subscribers
   *
   * @param subscriber the subscriber to be removed
   */
  public async unsubscribe(subscriber: Subscriber): Promise<void> {
    const index = this.subscribers.indexOf(subscriber)
    this.subscribers.splice(index, 1)
  }

  /**
   * Notify all subscribers that a change event was triggered for a specific item
   *
   * @param itemName the name of the item that changed
   */
  async notifySubscribers(itemName: string): Promise<void> {
    for (const subscriber of this.subscribers) {
      subscriber.update(itemName)
    }
  }
}
