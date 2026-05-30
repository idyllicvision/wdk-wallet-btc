// Unit-test Jest config. Unlike the default (integration) config, this one does
// NOT load the regtest globalSetup/globalTeardown, so it runs without Bitcoin
// Core / Electrs. Native Bare-runtime modules are mapped to Node-compatible
// mocks so the signer modules can be imported under Node.
export default {
  testEnvironment: 'node',
  testMatch: ['**/tests/unit/**/*.test.js'],
  moduleNameMapper: {
    '^bare-buffer$': '<rootDir>/tests/unit/__mocks__/bare-buffer.js',
    '^@idyllicvision/bare-universal-signer$':
      '<rootDir>/tests/unit/__mocks__/bare-universal-signer.js'
  },
  transform: {}
}
