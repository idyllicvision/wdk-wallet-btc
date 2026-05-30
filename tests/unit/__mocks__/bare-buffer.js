// Manual mock for `bare-buffer` used by the unit test project.
// The real module is a native addon for the Bare runtime and cannot load
// under Node. Node's built-in Buffer is API-compatible for our needs.

const NodeBuffer = globalThis.Buffer

export { NodeBuffer as Buffer }
