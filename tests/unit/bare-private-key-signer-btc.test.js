'use strict'

import { Buffer } from 'node:buffer'
import { networks, payments, Psbt } from 'bitcoinjs-lib'
import bitcoinMessageModule from 'bitcoinjs-message'

import BarePrivateKeySignerBtc from '../../src/signers/bare-private-key-signer-btc.js'
import { createMockBareSigner, expectedAddress } from './helpers/mock-bare-signer.js'

const bitcoinMessage = bitcoinMessageModule.default ?? bitcoinMessageModule

const newSigner = (config = {}) =>
  new BarePrivateKeySignerBtc({ bareSigner: createMockBareSigner(), ...config })

describe('BarePrivateKeySignerBtc', () => {
  describe('constructor / config', () => {
    test('applies defaults (bip 84, network bitcoin) and flags', () => {
      const signer = newSigner()
      expect(signer.isPrivateKey).toBe(true)
      expect(signer.isActive).toBe(true)
      expect(signer.config.bip).toBe(84)
    })

    test('accepts the supported networks', () => {
      for (const network of ['bitcoin', 'testnet', 'regtest']) {
        expect(() => newSigner({ network })).not.toThrow()
      }
    })

    test('rejects an invalid bip', () => {
      expect(() => newSigner({ bip: 49 })).toThrow('Invalid BIP')
    })

    test('rejects an invalid network', () => {
      expect(() => newSigner({ network: 'mainnet' })).toThrow('Invalid network')
    })
  })

  describe('unsupported HD operations', () => {
    test('derive() throws (no derivation for private-key signers)', () => {
      expect(() => newSigner().derive()).toThrow('derivation is not supported')
    })

    test('getExtendedPublicKey() rejects', async () => {
      await expect(newSigner().getExtendedPublicKey()).rejects.toThrow(
        'extended public key is unavailable'
      )
    })
  })

  describe('getPublicKey / getAddress', () => {
    test('getPublicKey returns the 33-byte compressed key from the bare signer', async () => {
      const bare = createMockBareSigner()
      const signer = new BarePrivateKeySignerBtc({ bareSigner: bare })
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
        const signer = new BarePrivateKeySignerBtc({ bareSigner: bare, network, bip })
        const address = await signer.getAddress()
        expect(address.startsWith(prefix)).toBe(true)
        expect(address).toBe(expectedAddress(bare.publicKey, network, bip))
      }
    )
  })

  describe('sign (message)', () => {
    test('produces a signature that verifies for the signer address (P2WPKH testnet)', async () => {
      const signer = newSigner({ network: 'testnet', bip: 84 })
      const address = await signer.getAddress()
      const message = 'hello from a unit test'

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
    test('signs an owned P2WPKH input and the PSBT finalizes', async () => {
      const bare = createMockBareSigner()
      const signer = new BarePrivateKeySignerBtc({ bareSigner: bare, network: 'testnet', bip: 84 })

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

    test('does not sign inputs that are not owned by the signer', async () => {
      const bare = createMockBareSigner()
      const signer = new BarePrivateKeySignerBtc({ bareSigner: bare, network: 'testnet', bip: 84 })

      // A foreign P2WPKH script (different key) the signer does not own.
      const foreign = createMockBareSigner(Buffer.from('22'.repeat(32), 'hex'))
      const { output: foreignScript } = payments.p2wpkh({
        pubkey: foreign.publicKey,
        network: networks.testnet
      })

      const psbt = new Psbt({ network: networks.testnet })
      psbt.addInput({ hash: '33'.repeat(32), index: 0, witnessUtxo: { script: foreignScript, value: 50_000 } })
      psbt.addOutput({ address: await signer.getAddress(), value: 40_000 })

      const before = bare.calls.sign
      await signer.signPsbt(psbt.toBase64())
      expect(bare.calls.sign).toBe(before) // never asked to sign a foreign input
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
