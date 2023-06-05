/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export interface CryptoProvider {
  arrayBufferToBase64(buffer: ArrayBuffer): string
}
