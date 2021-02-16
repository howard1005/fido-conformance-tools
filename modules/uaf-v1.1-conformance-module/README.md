FIDO UAF v1.1 Conformance Module
===

This is a Mocha based conformance module that does all of the conformance testing for the UAFv1.1

Any issues please report to [fido-alliance/conformance-tool-issues](https://github.com/fido-alliance/conformance-tool-issues)

## Structure

  - `manifesto.json` - Manifesto that defines conformance module. Contains module info, execution dependencies, and links to test lists.
  - `*-testlist.json` - A test list that contains reference to the mocha test files and how they have to execute.
  - `schemes` - contains JSON schemes
  - `docs` - contains relevant documentation files
  - `metadata` - contains server metadata for conformance testing
  - `client` - contains client tests
  - `server` - contains server tests
  - `js` - contains dependencies
  - `static_json_responses` - contains template JSON responses

## Dependencies

 - Cordova UAFv1.0 related API's plugin - https://github.com/fido-alliance/uaf-v1.0-conformance-module-cordova
 - UAF DOM API Cordova plugin - https://github.com/fido-alliance/uaf-client-cordova-plugin
 - UAF ASM API Cordova plugin - https://github.com/fido-alliance/uaf-asm-cordova-plugin
