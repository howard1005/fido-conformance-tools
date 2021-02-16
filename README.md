Conformance Tools Electron
===

Electron app for FIDO Conformance Testing

Any issues please report to [fido-alliance/conformance-tool-issues](https://github.com/fido-alliance/conformance-tool-issues)

# Protocols

Currently supporting:

- FIDO2
    + HID
    + NFC
    + BLE
    + WebAuthn client API
    + Server
- UAF v1.0
    + iOS x-callback-url
    + Android intent
    + Client
    + ASM
    + Combo
    + Server
- UAF v1.1
    + iOS x-callback-url
    + Android intent
    + Client
    + ASM
    + Combo
    + Server
- U2F v1.1
    + HID
    + NFC
    + BLE
    + Server

# Development

You are required `node.js` and `npm` installed

 - Clone this repo
 - `npm install` - install dependencies
 - `git submodule init` - initialize submodules
 - `git submodule update` - update submodules
 - `npm run start`

## Building

 - `npm run build:all`   - to run build for all operating systems
 - `npm run build:osx`   - to run build for osx (OSX only)
 - `npm run build:win32` - to run build for windows32 (Windows and Linux only)
 - `npm run build:linux` - to run build for windows32 (Linux and OSX only)
