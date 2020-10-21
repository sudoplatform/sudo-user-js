import { Subscriber } from './subscriber'

export interface Publisher {
  subscribe(subscriber: Subscriber): void
  unsubscribe(subscriber: Subscriber): void
  notifySubscribers(itemName: string): void
}
