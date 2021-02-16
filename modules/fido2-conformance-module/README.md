FIDO2 Conformance Module
===

This a Mocha based conformance module that does all of the conformance testing for the FIDO2

Any issues please report to [fido-alliance/conformance-tool-issues](https://github.com/fido-alliance/conformance-tool-issues)

## Structure

  - `manifesto.json` - Manifesto that defines conformance module. Contains module info, execution dependencies, and links to test lists.
  - `*-testlist.json` - A test list that contains reference to the mocha test files and how they have to execute.
  - `js` - contains dependencies
  - `test` - contains all of the tests
  - `metadata` - contains metadata statements for server tests
  - `pki` - contains PKI certs for conformance testing

## Dependencies

  - [fido-alliance/fido-conformance-tools-electron](https://github.com/fido-alliance/fido-conformance-tools-electron)
