/*
 * Copyright © 2023 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

type Resolver<T> = (value: T) => void

export type ResolvablePromise<T> = Promise<T> & { resolve: Resolver<T> }

/**
 * A promise that can be resolved externally
 */
export function createResolvablePromise<T>(): ResolvablePromise<T> {
  let resolve: Resolver<T>

  const promise = new Promise<T>((r) => {
    resolve = r
  })

  return Object.assign(promise, {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore: Assign before use
    //   `resolve` is assigned during construction of the promise
    resolve,
  })
}
