// Manual mock for `@idyllicvision/bare-universal-signer` used by the unit test
// project. The real module depends on Bare-runtime native addons (bare-type,
// etc.) that cannot load under Node. The unit tests inject their own mock bare
// signer through the signer `config.bareSigner` option, so this stub only needs
// to satisfy the top-level `import { Signer }` and `getDefaultBareSigner`.

export class Signer {
  constructor (opts = {}) {
    this._opts = opts
  }

  async sign () {
    throw new Error('mock Signer.sign should not be called in unit tests')
  }

  async getPublicKey () {
    throw new Error('mock Signer.getPublicKey should not be called in unit tests')
  }
}
