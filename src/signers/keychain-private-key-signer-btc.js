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
 * @property {'mainnet'|'testnet'} [network='testnet']
 * @property {Object} [keychainOpts={}]
 */

/**
 * BTC signer backed by a raw private key stored in the iOS Keychain.
 * Compatible with ISignerBtc (wdk-wallet-btc). No HD derivation supported.
 */
export default class PrivateKeySignerBtc {
  /**
   * @param {PrivateKeySignerBtcConfig} [config={}]
   */
  constructor (config = {}) {
    if (config.bip && ![44, 84].includes(config.bip)) {
      throw new Error('Invalid BIP: must be 44 or 84')
    }
    if (config.network && !['mainnet', 'testnet'].includes(config.network)) {
      throw new Error('Invalid network: must be mainnet or testnet')
    }

    this._bareSigner = config.bareSigner ||
      new Signer({ secretType: 'privateKey', autoLockMs: 30000, opts: config.keychainOpts || {} })
    this._bip = config.bip || 84
    this._network = config.network || 'testnet'
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
    const networkName = this._network === 'mainnet' ? 'bitcoin' : this._network
    const network = networks[networkName] || networks.testnet
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
        return { signature: Buffer.from(sig), recovery: sig[0] }
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

    const networkName = this._network === 'mainnet' ? 'bitcoin' : this._network
    const network = networks[networkName] || networks.testnet
    const myScript = buildPaymentScript(this._bip, pubkey, network)

    for (let i = 0; i < psbtInstance.inputCount; i++) {
      const { input, prevOut, isOurs } = detectInputOwnership(psbtInstance, i, myScript)
      if (!isOurs) continue

      try {
        ensureWitnessUtxoIfNeeded(psbtInstance, i, this._bip, prevOut, input)

        await psbtInstance.signInputAsync(i, {
          publicKey: pubkey,
          sign: (hash) =>
            this._bareSigner
              .sign({ curve: 'secp256k1', data: hash })
              .then((sig) => {
                const buf = Buffer.from(sig)
                // signInput expects 64-byte r||s; strip recovery byte if present
                return buf.length === 65 ? buf.subarray(1) : buf
              })
        })
      } catch (err) {
        console.warn(`PrivateKeySignerBtc: skipping input ${i}:`, err.message)
      }
    }

    return psbtInstance.toBase64()
  }

  dispose () { this._isActive = false }
}
