/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { Subscriber } from './subscriber'

export interface Publisher {
  subscribe(subscriber: Subscriber): void
  unsubscribe(subscriber: Subscriber): void
  notifySubscribers(itemName: string): void
}
