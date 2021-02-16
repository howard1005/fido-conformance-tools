FIDO U2F v1.1 Conformance Module
===

This is a Mocha based conformance module that does all of the conformance testing for the U2Fv1.1

Any issues please report to [fido-alliance/conformance-tool-issues](https://github.com/fido-alliance/conformance-tool-issues)

## Structure

  - `manifesto.json` - Manifesto that defines conformance module. Contains module info, execution dependencies, and links to test lists.
  - `*-testlist.json` - A test list that contains reference to the mocha test files and how they have to execute.
  - `js` - contains dependencies
  - `test` - contains all of the tests

## Dependencies

  - [fido-alliance/fido-conformance-tools-electron](https://github.com/fido-alliance/fido-conformance-tools-electron)
