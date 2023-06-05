/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { CryptoProvider } from '../../core/crypto'

export const cryptoProvider: CryptoProvider = {
  arrayBufferToBase64: (buffer: ArrayBuffer): string => {
    return Buffer.from(buffer).toString('base64')
  },
}
