import { SudoKeyManager } from '@sudoplatform/sudo-common'
import { anything, capture, instance, mock, reset, verify } from 'ts-mockito'
import { DefaultKeyManager } from '../../src/core/key-manager'

const commonKeyManagerMock = mock<SudoKeyManager>()

describe('KeyManager Test Suite', () => {
  let instanceUnderTest: DefaultKeyManager
  beforeEach(() => {
    reset(commonKeyManagerMock)
    instanceUnderTest = new DefaultKeyManager(instance(commonKeyManagerMock))
  })
  describe('addString', () => {
    it('passes a buffer to the sudo key manager instance', async () => {
      await instanceUnderTest.addString('dummyKeyId', 'dummyValue')
      verify(commonKeyManagerMock.addPassword(anything(), anything())).once()
      const [actualBuffer, actualKeyId] = capture(
        commonKeyManagerMock.addPassword,
      ).first()
      expect(actualBuffer).toBeInstanceOf(ArrayBuffer)
      expect(actualBuffer).toStrictEqual(
        new TextEncoder().encode('dummyValue').buffer,
      )
      expect(actualKeyId).toStrictEqual('dummyKeyId')
    })
  })
})
