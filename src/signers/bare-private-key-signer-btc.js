'use strict'

import { Buffer } from 'bare-buffer'
import { networks, Psbt } from 'bitcoinjs-lib'
import bitcoinMessageModule from 'bitcoinjs-message'

import { Signer } from '@idyllicvision/bare-universal-signer'
import {
  buildPaymentScript,
  detectInputOwnership,
  ensureWitnessUtxoIfNeeded,
  normalizeConfig,
  getAddressFromPublicKey
} from '../utils.js'

const bitcoinMessage = bitcoinMessageModule.default ?? bitcoinMessageModule

globalThis.Buffer = Buffer

/**
 * @typedef {Object} PrivateKeySignerBtcConfig
 * @property {import('@idyllicvision/bare-universal-signer').Signer} [bareSigner] - Pre-constructed Signer instance
 * @property {number} [bip=84]
 * @property {'bitcoin'|'testnet'|'regtest'} [network='bitcoin']
 * @property {Object} [keychainOpts={}]
 */

// Networks supported across the package (matches WalletAccountReadOnlyBtc and
// bitcoinjs-lib's `networks` keys). 'bitcoin' is mainnet.
const VALID_NETWORKS = ['bitcoin', 'testnet', 'regtest']
const defaultNetwork = 'bitcoin'

// Resolve a package network name to a bitcoinjs-lib network object.
function resolveBitcoinNetwork (network) {
  return networks[network] || networks.bitcoin
}

/**
 * BTC signer backed by a raw private key stored in the iOS Keychain.
 * Compatible with ISignerBtc (wdk-wallet-btc). No HD derivation supported.
 */
export default class BarePrivateKeySignerBtc {
  /**
   * @param {PrivateKeySignerBtcConfig} [config={}]
   */
  constructor (config = {}) {
    if (config.bip && ![44, 84].includes(config.bip)) {
      throw new Error('Invalid BIP: must be 44 or 84')
    }
    if (config.network && !VALID_NETWORKS.includes(config.network)) {
      throw new Error(`Invalid network: must be one of ${VALID_NETWORKS.join(', ')}`)
    }

    this._bareSigner = config.bareSigner ||
      new Signer({ secretType: 'privateKey', autoLockMs: 30000, opts: config.keychainOpts || {} })
    this._bip = config.bip || 84
    this._network = config.network || defaultNetwork
    this._config = normalizeConfig({ bip: this._bip, network: this._network })
    this._isActive = true
    this._isPrivateKey = true
  }

  get isPrivateKey () { return this._isPrivateKey }
  get isActive () { return this._isActive }
  get config () { return this._config }

  /** @throws {Error} Always */
  derive () {
    throw new Error('PrivateKeySignerBtc: derivation is not supported for private-key signers.')
  }

  /** @throws {Error} Always */
  async getExtendedPublicKey () {
    throw new Error('PrivateKeySignerBtc: extended public key is unavailable for private-key signers.')
  }

  /** @returns {Promise<Uint8Array>} 33-byte compressed public key */
  async getPublicKey () {
    return this._bareSigner.getPublicKey({ curve: 'secp256k1' })
  }

  /** @returns {Promise<string>} Bitcoin address */
  async getAddress () {
    const pubkey = Buffer.from(await this.getPublicKey())
    const network = resolveBitcoinNetwork(this._network)
    return getAddressFromPublicKey(pubkey, network, this._bip)
  }

  /**
   * Sign a message.
   * @param {string} message
   * @returns {Promise<Buffer>}
   */
  async sign (message) {
    const signer = {
      sign: async (hash) => {
        const hashBuf = Buffer.isBuffer(hash) ? hash : Buffer.from(hash)
        const sig = await this._bareSigner.sign({ curve: 'secp256k1', data: hashBuf })
        // Bare signer returns 65 bytes [recovery(1), r(32), s(32)].
        // bitcoinjs-message expects the 64-byte r||s separately from recovery.
        const buf = Buffer.from(sig)
        return { signature: buf.subarray(1), recovery: buf[0] }
      }
    }
    return bitcoinMessage.signAsync(
      message,
      signer,
      true,
      this._bip === 84 ? { segwitType: 'p2wpkh' } : undefined
    )
  }

  /**
   * Sign a PSBT.
   * @param {string|Psbt} psbt
   * @returns {Promise<string>} Signed PSBT base64
   */
  async signPsbt (psbt) {
    const psbtInstance = typeof psbt === 'string' ? Psbt.fromBase64(psbt) : psbt

    const pubkeyRaw = await this.getPublicKey()
    if (!pubkeyRaw) return psbtInstance.toBase64()
    const pubkey = Buffer.from(pubkeyRaw)

    const network = resolveBitcoinNetwork(this._network)
    const myScript = buildPaymentScript(this._bip, pubkey, network)

    const errors = []

    for (let i = 0; i < psbtInstance.inputCount; i++) {
      const { input, prevOut, isOurs } = detectInputOwnership(psbtInstance, i, myScript)
      if (!isOurs) continue

      try {
        ensureWitnessUtxoIfNeeded(psbtInstance, i, this._bip, prevOut, input)

        await psbtInstance.signInputAsync(i, {
          publicKey: pubkey,
          sign: async (hash) => {
            const sig = await this._bareSigner.sign({ curve: 'secp256k1', data: hash })
            const buf = Buffer.from(sig.signature || sig)
            // signInput expects 64-byte r||s; strip recovery byte if present
            return buf.length === 65 ? buf.subarray(1) : buf
          }
        })
      } catch (err) {
        // Only owned inputs reach here; a failure means the PSBT is not fully
        // signed. Collect and throw after the loop so callers are not handed a
        // PSBT that looks signed but is not.
        errors.push(new Error(`Failed to sign input ${i}: ${err.message}`))
      }
    }

    if (errors.length > 0) {
      throw new Error(
        `signPsbt failed for ${errors.length} input(s): ${errors.map((e) => e.message).join('; ')}`
      )
    }

    return psbtInstance.toBase64()
  }

  dispose () { this._isActive = false }
}
