'use strict'

import { Buffer } from 'node:buffer'
import { networks, payments, Psbt } from 'bitcoinjs-lib'
import bitcoinMessageModule from 'bitcoinjs-message'

import BareSeedBtcSigner from '../../src/signers/bare-seed-btc-signer.js'
import { createMockBareSigner, expectedAddress } from './helpers/mock-bare-signer.js'

const bitcoinMessage = bitcoinMessageModule.default ?? bitcoinMessageModule

const newSigner = (config = {}) =>
  new BareSeedBtcSigner({ bareSigner: createMockBareSigner(), ...config })

describe('BareSeedBtcSigner', () => {
  describe('constructor / config', () => {
    test('is a root signer with normalized config', () => {
      const signer = newSigner({ bip: 84, network: 'testnet' })
      expect(signer.isRoot).toBe(true)
      expect(signer.isActive).toBe(true)
      expect(signer.config.bip).toBe(84)
    })

    test('rejects invalid bip / network / path', () => {
      expect(() => newSigner({ bip: 49 })).toThrow('Invalid BIP')
      expect(() => newSigner({ network: 'mainnet' })).toThrow('Invalid network')
      expect(() => newSigner({ path: 'not-a-path' })).toThrow('path')
    })
  })

  describe('derive', () => {
    test('builds the expected full path and returns a non-root child', () => {
      const root = newSigner({ bip: 84, network: 'testnet', path: "m/84'/1'" })
      const child = root.derive("0'/0/0")

      expect(child).toBeInstanceOf(BareSeedBtcSigner)
      expect(child.isRoot).toBe(false)
      expect(child.path).toBe("m/84'/1'/0'/0/0") // testnet coin type = 1
      expect(child.index).toBe(0)
    })

    test('uses coin type 0 for mainnet (bitcoin)', () => {
      const root = newSigner({ bip: 84, network: 'bitcoin', path: "m/84'/0'" })
      expect(root.derive("0'/0/5").path).toBe("m/84'/0'/0'/0/5")
    })

    test('rejects a malformed relative path', () => {
      expect(() => newSigner().derive('bad/path/')).toThrow()
    })
  })

  describe('getPublicKey / getAddress', () => {
    test('getPublicKey returns the 33-byte compressed key', async () => {
      const bare = createMockBareSigner()
      const signer = new BareSeedBtcSigner({ bareSigner: bare, network: 'testnet' })
      const pubkey = Buffer.from(await signer.getPublicKey())
      expect(pubkey.length).toBe(33)
      expect(pubkey.equals(bare.publicKey)).toBe(true)
    })

    test.each([
      { network: 'testnet', bip: 84, prefix: 'tb1q' },
      { network: 'bitcoin', bip: 84, prefix: 'bc1q' },
      { network: 'bitcoin', bip: 44, prefix: '1' }
    ])(
      'getAddress: $network bip$bip → $prefix and matches an independent derivation',
      async ({ network, bip, prefix }) => {
        const bare = createMockBareSigner()
        const signer = new BareSeedBtcSigner({ bareSigner: bare, network, bip })
        const address = await signer.getAddress()
        expect(address.startsWith(prefix)).toBe(true)
        expect(address).toBe(expectedAddress(bare.publicKey, network, bip))
      }
    )

    test('getExtendedPublicKey() rejects (not implemented)', async () => {
      await expect(newSigner().getExtendedPublicKey()).rejects.toThrow()
    })
  })

  describe('sign (message)', () => {
    test('produces a signature that verifies for the signer address (P2WPKH testnet)', async () => {
      const signer = newSigner({ network: 'testnet', bip: 84, path: "m/84'/1'/0'/0/0" })
      const address = await signer.getAddress()
      const message = 'seed signer message test'

      const signature = await signer.sign(message)

      const ok = bitcoinMessage.verify(
        message,
        address,
        signature.toString('base64'),
        undefined,
        true
      )
      expect(ok).toBe(true)
    })
  })

  describe('signPsbt', () => {
    test('signs an owned P2WPKH input (HD) and the PSBT finalizes', async () => {
      const bare = createMockBareSigner()
      const signer = new BareSeedBtcSigner({
        bareSigner: bare,
        network: 'testnet',
        bip: 84,
        path: "m/84'/1'/0'/0/0"
      })

      const network = networks.testnet
      const { output: script } = payments.p2wpkh({ pubkey: bare.publicKey, network })

      const psbt = new Psbt({ network })
      psbt.addInput({
        hash: '11'.repeat(32),
        index: 0,
        witnessUtxo: { script, value: 100_000 }
      })
      psbt.addOutput({ address: await signer.getAddress(), value: 90_000 })

      const signedBase64 = await signer.signPsbt(psbt.toBase64())
      const signed = Psbt.fromBase64(signedBase64)
      signed.finalizeAllInputs()
      const tx = signed.extractTransaction()

      expect(tx.getId()).toMatch(/^[0-9a-f]{64}$/)
      expect(bare.calls.sign).toBeGreaterThan(0)
    })
  })

  describe('dispose', () => {
    test('marks the signer inactive', () => {
      const signer = newSigner()
      signer.dispose()
      expect(signer.isActive).toBe(false)
    })
  })
})
