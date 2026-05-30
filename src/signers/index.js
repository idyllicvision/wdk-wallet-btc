'use strict'

/**
 * Barrel exports for BTC signers.
 *
 * - `BtcSigner`: keychain-based HD signer via bare-universal-signer (iOS Keychain).
 * - `BareHDSigner`: low-level HD signer helper used internally by BtcSigner.
 * - `PrivateKeyBtcSigner`: keychain-based private key signer via bare-universal-signer.
 */
export { default as BtcSigner, BareHDSigner } from './bare-seed-btc-signer.js'
export { default as PrivateKeyBtcSigner } from './bare-private-key-signer-btc.js'
