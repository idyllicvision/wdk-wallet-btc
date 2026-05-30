'use strict'

import { Buffer } from 'node:buffer'
import * as ecc from '@bitcoinerlab/secp256k1'
import { networks, payments } from 'bitcoinjs-lib'

// A fixed 32-byte private key so the unit tests are deterministic.
export const TEST_PRIVATE_KEY = Buffer.from('11'.repeat(32), 'hex')

/**
 * Builds a mock `@idyllicvision/bare-universal-signer` backed by a real
 * secp256k1 key. Because the signatures it returns are genuine, message/PSBT
 * signatures produced by the signer-under-test actually verify.
 *
 * Shape matches what the BTC signers call:
 *   - `getPublicKey({ path?, curve, opts? })` → 33-byte compressed public key
 *   - `sign({ path?, curve, data })` → 65-byte `[recovery(1), r(32), s(32)]`
 *
 * The mock ignores `path`, so every derivation maps to the same key — which is
 * all the unit tests need (they assert format/round-trip, not HD vectors).
 *
 * @param {Buffer} [privateKey] - 32-byte private key (defaults to TEST_PRIVATE_KEY).
 */
export function createMockBareSigner (privateKey = TEST_PRIVATE_KEY) {
  const priv = Uint8Array.from(privateKey)
  const pub = ecc.pointFromScalar(priv, true) // 33-byte compressed

  return {
    calls: { sign: 0, getPublicKey: 0 },
    publicKey: Buffer.from(pub),
    async getPublicKey () {
      this.calls.getPublicKey++
      return Uint8Array.from(pub)
    },
    async sign ({ data }) {
      this.calls.sign++
      const { signature, recoveryId } = ecc.signRecoverable(
        Uint8Array.from(data),
        priv
      )
      const out = Buffer.alloc(65)
      out[0] = recoveryId
      Buffer.from(signature).copy(out, 1)
      return out
    }
  }
}

/**
 * Computes the expected address for a public key, independently of the signer,
 * so address assertions are not circular.
 *
 * @param {Buffer} pubkey - Compressed public key.
 * @param {string} network - 'bitcoin' | 'testnet' | 'regtest'.
 * @param {number} bip - 44 (P2PKH) or 84 (P2WPKH).
 */
export function expectedAddress (pubkey, network, bip) {
  const net = networks[network] || networks.bitcoin
  const { address } =
    bip === 44
      ? payments.p2pkh({ pubkey: Buffer.from(pubkey), network: net })
      : payments.p2wpkh({ pubkey: Buffer.from(pubkey), network: net })
  return address
}
