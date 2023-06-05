/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export interface ProtectedStore {
  put(key: string, value: ArrayBuffer): Promise<void>
  get(key: string): Promise<ArrayBuffer>
  delete(key: string): Promise<void>
}
