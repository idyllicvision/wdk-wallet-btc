'use strict'

import { payments, Transaction } from 'bitcoinjs-lib'

/**
 * Build payment script for the given BIP type.
 * @param {number} bip - BIP standard (44 or 84)
 * @param {Buffer} pubkey - Public key buffer
 * @param {object} network - Bitcoin network object
 * @returns {Buffer} Payment script
 */
export function buildPaymentScript (bip, pubkey, network) {
  const payment =
    bip === 84
      ? payments.p2wpkh({ pubkey, network })
      : payments.p2pkh({ pubkey, network })
  return payment.output
}

/**
 * Detect if a PSBT input belongs to the signer.
 * @param {import('bitcoinjs-lib').Psbt} psbtInstance - PSBT instance
 * @param {number} i - Input index
 * @param {Buffer} myScript - Script to match
 * @returns {{input: object, prevOut: object|null, isOurs: boolean}}
 */
export function detectInputOwnership (psbtInstance, i, myScript) {
  const input = psbtInstance.data.inputs[i] || {}
  const txIn = psbtInstance.txInputs[i]
  let prevOut = null
  let isOurs = false

  try {
    if (input.nonWitnessUtxo) {
      const prevTx = Transaction.fromBuffer(input.nonWitnessUtxo)
      prevOut = prevTx.outs[txIn.index]
      isOurs = !!(
        prevOut &&
        prevOut.script &&
        myScript &&
        prevOut.script.equals(myScript)
      )
    } else if (input.witnessUtxo) {
      prevOut = input.witnessUtxo
      isOurs = !!(
        prevOut &&
        prevOut.script &&
        myScript &&
        prevOut.script.equals(myScript)
      )
    }
  } catch (err) {
    isOurs = false
  }
  return { input, prevOut, isOurs }
}

/**
 * Ensure witnessUtxo is set for SegWit inputs.
 * @param {import('bitcoinjs-lib').Psbt} psbtInstance - PSBT instance
 * @param {number} i - Input index
 * @param {number} bip - BIP standard
 * @param {object} prevOut - Previous output
 * @param {object} input - Input object
 */
export function ensureWitnessUtxoIfNeeded (psbtInstance, i, bip, prevOut, input) {
  try {
    if (
      bip === 84 &&
      prevOut &&
      prevOut.script &&
      typeof prevOut.value === 'number' &&
      !input.witnessUtxo
    ) {
      psbtInstance.updateInput(i, {
        witnessUtxo: {
          script: prevOut.script,
          value: prevOut.value
        }
      })
    }
  } catch (err) {
    console.error('ensureWitnessUtxoIfNeeded', err)
  }
}

/**
 * Get Bitcoin address from public key.
 * @param {Buffer} publicKey - Public key buffer
 * @param {object} network - Bitcoin network object
 * @param {number} [bip=44] - BIP standard (44 or 84)
 * @returns {string} Bitcoin address
 */
export function getAddressFromPublicKey (publicKey, network, bip = 44) {
  const { address } =
    bip === 44
      ? payments.p2pkh({ pubkey: publicKey, network })
      : payments.p2wpkh({ pubkey: publicKey, network })
  return address
}

/**
 * Normalize signer configuration.
 * @param {object} [config={}] - Configuration object
 * @returns {object} Normalized configuration
 */
export function normalizeConfig (config = {}) {
  const bip = config.bip ?? 84
  if (![44, 84].includes(bip)) {
    throw new Error('Invalid bip specification. Supported bips: 44, 84.')
  }
  return { ...config, bip }
}
