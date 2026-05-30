'use strict'

import { Buffer } from 'bare-buffer'
import { networks, Psbt, crypto } from 'bitcoinjs-lib'
import bitcoinMessageModule from 'bitcoinjs-message'

import { getDefaultBareSigner } from '../bare-signer.js'
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
 * @typedef {Object} BtcSignerConfig
 * @property {import('@idyllicvision/bare-universal-signer').Signer} [bareSigner] - Signer instance
 * @property {number} [bip=84] - BIP standard (44 or 84)
 * @property {string} [path] - Derivation path
 * @property {'bitcoin'|'testnet'|'regtest'} [network='bitcoin'] - Network
 * @property {Object} [keychainOpts={}] - Keychain options
 */

/**
 * HD Signer wrapper for bare-signer that implements the interface
 * required by bitcoinjs-lib for PSBT signing.
 */
export class BareHDSigner {
  /**
   * @param {import('@idyllicvision/bare-universal-signer').Signer} bareSigner - The bare-signer instance
   * @param {string} [path='m'] - Derivation path
   * @param {object} [opts={}] - Options including masterFingerprint, publicKey, and keychainOpts
   */
  constructor (
    bareSigner,
    path = 'm',
    opts = {
      masterFingerprint: null,
      publicKey: null,
      keychainOpts: {}
    }
  ) {
    this._bareSigner = bareSigner
    this._path = path
    this._masterFingerprint = opts.masterFingerprint || null
    this._publicKey = opts.publicKey || null
    this._keychainOpts = opts.keychainOpts || {}
  }

  /**
   * Derive a child signer from this signer.
   * @param {string} path - Full derivation path
   * @returns {BareHDSigner}
   */
  derivePath (path) {
    if (!/^m(\/\d+'?)+$/.test(path)) {
      throw new Error('Invalid path format')
    }
    if (path === this._path && this._publicKey) {
      return new BareHDSigner(this._bareSigner, path, {
        masterFingerprint: this._masterFingerprint,
        publicKey: this._publicKey,
        keychainOpts: this._keychainOpts
      })
    }
    return new BareHDSigner(this._bareSigner, path, {
      masterFingerprint: this._masterFingerprint,
      publicKey: this._publicKey,
      keychainOpts: this._keychainOpts
    })
  }

  /**
   * Sign a hash.
   * @param {Buffer} hash - 32-byte hash to sign
   * @returns {Promise<Buffer>} 64-byte signature (r || s)
   */
  sign (hash) {
    return this._bareSigner
      .sign({
        path: this._path,
        curve: 'secp256k1',
        data: hash,
        opts: this._keychainOpts
      })
      .then((sig) => {
        const sigBuffer = Buffer.from(sig)
        if (sigBuffer.length === 65) {
          return sigBuffer.subarray(1)
        }
        if (sigBuffer.length !== 64) {
          throw new Error(
            `Invalid signature length: expected 64 bytes, got ${sigBuffer.length}`
          )
        }
        return sigBuffer
      })
  }

  /**
   * Get the public key for this signer.
   * @returns {Buffer}
   */
  get publicKey () {
    if (!this._publicKey) {
      throw new Error(
        `publicKey not pre-calculated for path ${this._path}. Pre-calculate it before creating BareHDSigner.`
      )
    }
    return Buffer.isBuffer(this._publicKey)
      ? this._publicKey
      : Buffer.from(this._publicKey)
  }

  /**
   * Get the master fingerprint.
   * @returns {Buffer}
   */
  get fingerprint () {
    if (!this._masterFingerprint) {
      throw new Error('masterFingerprint must be provided to BareHDSigner')
    }
    return Buffer.isBuffer(this._masterFingerprint)
      ? this._masterFingerprint
      : Buffer.from(this._masterFingerprint)
  }
}

const defaultPath = "m/84'/0'/0'/0/0"
const defaultBIP = 84
const defaultNetwork = 'bitcoin'

// Networks supported across the package (matches WalletAccountReadOnlyBtc and
// bitcoinjs-lib's `networks` keys). 'bitcoin' is mainnet.
const VALID_NETWORKS = ['bitcoin', 'testnet', 'regtest']

// BIP-44 coin type: mainnet ('bitcoin') = 0, all test networks = 1.
function coinTypeForNetwork (network) {
  return network === 'bitcoin' ? '0' : '1'
}

// Resolve a package network name to a bitcoinjs-lib network object.
function resolveBitcoinNetwork (network) {
  return networks[network] || networks.bitcoin
}

/**
 * Bitcoin signer with BIP-44/84 support.
 */
export default class BareSeedBtcSigner {
  /**
   * Create a new BTC signer.
   * @param {BtcSignerConfig} [config={}] - Configuration options
   */
  constructor (
    config = {
      bareSigner: null,
      bip: 84,
      path: defaultPath,
      network: defaultNetwork,
      keychainOpts: {}
    }
  ) {
    // Validate config
    if (config.bip && ![44, 84].includes(config.bip)) {
      throw new Error('Invalid BIP: must be 44 or 84')
    }
    if (config.network && !VALID_NETWORKS.includes(config.network)) {
      throw new Error(`Invalid network: must be one of ${VALID_NETWORKS.join(', ')}`)
    }
    if (config.path && !/^m(\/\d+'?)+$/.test(config.path)) {
      throw new Error('Invalid path format')
    }

    // Auto-initialize with default bare-signer if not provided
    this._bareSigner = config.bareSigner || getDefaultBareSigner()
    this._keychainOpts = config.keychainOpts || {}
    this._isActive = true
    this._bip = config.bip || defaultBIP
    this._path = config.path || defaultPath
    this._network = config.network || defaultNetwork
    this._isRoot = true
    this._config = normalizeConfig({
      bip: this._bip,
      network: this._network
    })
  }

  /**
   * Create a signer from an extended private key.
   * @throws {Error} Not supported for hardware-based signers
   */
  static fromXprv (xprv, bareSigner, config = {}) {
    throw new Error('fromXprv not supported: use seed-based derivation instead')
  }

  /** @returns {boolean} Whether this is a root signer */
  get isRoot () {
    return this._isRoot
  }

  /** @returns {boolean} Whether the signer is active */
  get isActive () {
    return this._isActive
  }

  /** @returns {number} Last path component as number */
  get index () {
    return +this._path.split('/').pop()
  }

  /** @returns {string} Current derivation path */
  get path () {
    return this._path
  }

  /** @returns {object} Signer configuration */
  get config () {
    return this._config
  }

  /** @returns {string|undefined} Bitcoin address */
  get address () {
    return this._address
  }

  /**
   * Derive a child signer from this signer.
   * @param {string} relPath - Relative derivation path (e.g., "0'/0/0")
   * @param {object} [config={}] - Optional configuration overrides
   * @returns {BareSeedBtcSigner} A new child signer with the derived path
   */
  derive (relPath, config = {}) {
    if (!relPath || typeof relPath !== 'string') {
      throw new Error('Invalid relative path: must be a non-empty string')
    }
    if (!/^(\d+'?\/)*\d+'?$/.test(relPath)) {
      throw new Error('Invalid relative path format: expected format like "0\'/0/0"')
    }

    // Construct full path: m/84'/0'/0'/0/0 for mainnet, m/84'/1'/0'/0/0 for testnet/regtest
    // relPath comes as "0'/0/0" (account/change/index)
    const coinType = coinTypeForNetwork(this._network)
    const fullPath = `m/${this._bip}'/${coinType}'/${relPath}`

    const childSigner = new BareSeedBtcSigner({
      bareSigner: this._bareSigner,
      bip: this._bip,
      path: fullPath,
      network: this._network,
      keychainOpts: this._keychainOpts
    })
    childSigner._isRoot = false
    return childSigner
  }

  /**
   * Get the Bitcoin address for this signer.
   * @returns {Promise<string>}
   */
  async getAddress () {
    const pubkey = await this._bareSigner.getPublicKey({
      path: this._path,
      curve: 'secp256k1',
      opts: this._keychainOpts
    })
    const pubkeyBuffer = Buffer.from(pubkey)
    const network = resolveBitcoinNetwork(this._network)
    const address = getAddressFromPublicKey(pubkeyBuffer, network, this._bip)
    return address
  }

  /**
   * Get the extended public key.
   * @throws {Error} Not implemented
   */
  async getExtendedPublicKey () {
    throw new Error('not implemented getExtendedPublicKey')
  }

  /**
   * Sign a PSBT.
   * @param {string|Psbt} psbt - PSBT as base64 string or Psbt instance
   * @returns {Promise<string>} Signed PSBT as base64
   */
  async signPsbt (psbt) {
    const psbtInstance = typeof psbt === 'string' ? Psbt.fromBase64(psbt) : psbt

    const pubkeyRaw = await this.getPublicKey()
    if (!pubkeyRaw) return psbtInstance.toBase64()
    const pubkey = Buffer.from(pubkeyRaw)

    if (!this._masterFingerprint) {
      this._masterFingerprint = await this._getMasterFingerprint()
    }
    const masterFingerprint = this._masterFingerprint

    if (!Buffer.isBuffer(masterFingerprint) || masterFingerprint.length !== 4) {
      throw new Error('Invalid master fingerprint format')
    }

    const network = resolveBitcoinNetwork(this._config.network)
    const myScript = buildPaymentScript(this._bip, pubkey, network)

    const errors = []

    for (let i = 0; i < psbtInstance.inputCount; i++) {
      const { input, prevOut, isOurs } = detectInputOwnership(
        psbtInstance,
        i,
        myScript
      )
      if (!isOurs) continue

      try {
        ensureWitnessUtxoIfNeeded(psbtInstance, i, this._bip, prevOut, input)

        const signerFingerprint = Buffer.from(masterFingerprint)
        const bareHdSigner = new BareHDSigner(this._bareSigner, this._path, {
          masterFingerprint: signerFingerprint,
          publicKey: pubkey,
          keychainOpts: this._keychainOpts
        })

        const signerFp = bareHdSigner.fingerprint

        const currentInput = psbtInstance.data.inputs[i] || {}
        const existingDerivations = currentInput.bip32Derivation || []

        const hasMatchingDerivation = this._hasMatchingDerivation(
          existingDerivations,
          pubkey,
          signerFp
        )

        if (!hasMatchingDerivation) {
          this._addBip32Derivation(
            psbtInstance,
            i,
            existingDerivations,
            pubkey,
            signerFp
          )
        }

        await psbtInstance.signInputHDAsync(i, bareHdSigner)
      } catch (err) {
        // Only inputs owned by this signer reach here (non-owned inputs are
        // skipped above). A failure means signing is incomplete, so collect
        // it and surface it after the loop rather than silently returning a
        // PSBT that looks fully signed.
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

  /**
   * Check if derivations contain a matching entry.
   * @private
   */
  _hasMatchingDerivation (derivations, pubkey, fingerprint) {
    return derivations.some(
      (d) =>
        d?.pubkey &&
        Buffer.isBuffer(d.pubkey) &&
        d.pubkey.equals(pubkey) &&
        d.masterFingerprint &&
        Buffer.isBuffer(d.masterFingerprint) &&
        d.masterFingerprint.equals(fingerprint) &&
        d.path === this.path
    )
  }

  /**
   * Add BIP32 derivation to a PSBT input.
   * @private
   */
  _addBip32Derivation (
    psbtInstance,
    inputIndex,
    existingDerivations,
    pubkey,
    fingerprint
  ) {
    const filteredDerivations = existingDerivations.filter(
      (d) =>
        !(
          d?.pubkey &&
          Buffer.isBuffer(d.pubkey) &&
          d.pubkey.equals(pubkey) &&
          d.path === this.path
        )
    )

    filteredDerivations.push({
      masterFingerprint: Buffer.from(fingerprint),
      path: this.path,
      pubkey: Buffer.from(pubkey)
    })

    psbtInstance.updateInput(inputIndex, {
      bip32Derivation: filteredDerivations
    })

    const updatedInput = psbtInstance.data.inputs[inputIndex]
    const updatedDerivations = updatedInput.bip32Derivation || []

    if (!this._hasMatchingDerivation(updatedDerivations, pubkey, fingerprint)) {
      throw new Error(`Failed to add BIP32 derivation to input ${inputIndex}`)
    }
  }

  /**
   * Sign a message.
   * @param {string} message - Message to sign
   * @returns {Promise<Buffer>} Signature
   */
  async sign (message) {
    const signer = {
      sign: (hash) => {
        if (!hash) {
          throw new Error('Hash is undefined or null')
        }
        if (!Buffer.isBuffer(hash)) {
          if (hash instanceof Uint8Array || hash.byteLength !== undefined) {
            hash = Buffer.from(hash)
          } else {
            throw new Error(
              `Hash must be a Buffer or Uint8Array, got ${typeof hash}`
            )
          }
        }
        return this._bareSigner
          .sign({
            path: this._path,
            curve: 'secp256k1',
            data: hash,
            opts: this._keychainOpts
          })
          .then((sig) => {
            if (!sig) {
              throw new Error('Signature is undefined')
            }
            // The bare signer returns a 65-byte recovered signature laid out
            // as [recovery(1), r(32), s(32)]. bitcoinjs-message expects the
            // 64-byte r||s in `signature` and the recovery id separately.
            const buf = Buffer.from(sig)
            return {
              signature: buf.subarray(1),
              recovery: buf[0]
            }
          })
          .catch((err) => {
            console.error('Error in signer.sign:', err)
            throw err
          })
      }
    }

    const signature = await bitcoinMessage.signAsync(
      message,
      signer,
      true,
      this._bip === 84 ? { segwitType: 'p2wpkh' } : undefined
    )
    return signature
  }

  /**
   * Get the public key.
   * @returns {Promise<Uint8Array>}
   */
  async getPublicKey () {
    return this._bareSigner.getPublicKey({
      path: this._path,
      curve: 'secp256k1',
      opts: this._keychainOpts
    })
  }

  /**
   * Get the master fingerprint (first 4 bytes of hash160 of master public key).
   * @private
   * @returns {Promise<Buffer>}
   */
  async _getMasterFingerprint () {
    const masterPubkey = await this._bareSigner.getPublicKey({
      path: 'm',
      curve: 'secp256k1',
      opts: this._keychainOpts
    })
    const hash160 = crypto.hash160(Buffer.from(masterPubkey))
    return Buffer.from(hash160.subarray(0, 4))
  }

  /**
   * Dispose of this signer and mark it inactive.
   */
  dispose () {
    this._isActive = false
  }
}

export { BareSeedBtcSigner as BtcSigner }
