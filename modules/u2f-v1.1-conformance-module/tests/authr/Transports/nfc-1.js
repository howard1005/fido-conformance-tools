/* -----

    COPYRIGHT FIDO ALLIANCE 2016-2020
    AUTHOR: YURIY ACKERMANN <YURIY@FIDOALLIANCE.ORG> <YURIY.ACKERMANN@GMAIL.COM>

    ANY MODIFICATION OF THIS CODE WITHOUT PRIOR CONCENT BY FIDO ALLIANCE
    WILL BE TREATED AS A BREACH OF THE FIDO ALLIANCE END USER LICENSE AGREEMENT
    AND WILL RESULT IN CANCELATION OF THE CONFORMANCE TEST RESULTS
    AND TOTAL AND COMPLETE BAN FROM THE FIDO CERTIFICATION PROGRAMME

    FOR ANY QUESTIONS CONTACT CERTIFICATION@FIDOALLIANCE.ORG

    YOU CAN DOWNLOAD EULA BY OPENING MENU -> LEGAL INFORMATION

+----- */
'use strict';

describe(`

        NFC-1

        Test U2F NFC support

    `, function() {

    before(function(){
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        if(getDeviceInfo().transport !== 'NFC')
            this.skip();
    })

    this.timeout(30000);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Send FIDO applet selection command and check that authenticator succeeds.

            For CTAP1(U2F) compatible authenticators check that authenticator returns 0x5532465F5632(U2F_V2) in response.

    `, () => {
        let appletSelectionCommand = new Uint8Array([0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00]);
        return navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), [appletSelectionCommand], true)
            .then((response) => {
                if(hex.encode(response[0]) !== '5532465f56329000')
                    throw new Error('For U2F compatible CTAP2 authenticators it MUST return legacy "U2F_V2" string!');
            })
    })

    it(`P-2

        Send a valid Register command, wrapped in Extended APDU, wait for the response, and check that Authenticator returns SW_NO_ERROR(0x9000) error code.

    `, () => {
        return sendValidCTAP_MSG(U2F_INS_REGISTER, generateGoodAPDURegisterFrame(), {'requireExtended': true})
            .then((result) => {
                assert.equal(APDU_STATUS_CODES.SW_NO_ERROR, result.statusCode, 'Authenticator returned an error: ' + result.statusCode);
            })
            .catch((result) => {
                throw new Error('Error sending Extended APDU request! Please check that your reader supports it!')
            })
    })

    it(`P-3

        Send a valid Register command, wrapped in Short APDU, wait for the response, and check that Authenticator returns SW_NO_ERROR(0x9000) error code.

    `, () => {
        return sendValidCTAP_MSG(U2F_INS_REGISTER, generateGoodAPDURegisterFrame())
            .then((result) => {
                assert.equal(APDU_STATUS_CODES.SW_NO_ERROR, result.statusCode, 'Authenticator returned an error: ' + result.statusCode);
            })
    })

    it(`P-4

        Send a valid Register command, wrapped in Short APDU with mixed sizes, wait for the response, and check that Authenticator returns SW_NO_ERROR(0x9000) error code.

    `, () => {

        let requestFrames = generateRandomlySizedShortAPDUCTAP1Frames(U2F_INS_REGISTER, generateGoodAPDURegisterFrame());
        return sendCTAPNFC_MSGCommand(requestFrames)
            .then((result) => {
                let authrResponse  = parseAPDUResponse(result);
                let statusCode     = authrResponse.SW12;

                if(statusCode !== APDU_STATUS_CODES.SW_NO_ERROR) {
                    throw new Error(`Expected authenticator to succeed with SW_NO_ERROR(${hexifyInt(APDU_STATUS_CODES.SW_NO_ERROR)}). Got ${APDU_STATUS_CODES[ctap1Response.statusCode]}(${ctap1Response.statusCode})`);
                }

                let responseRaw    = authrResponse.DATA;
                let responseStruct = parseCTAP1RegistrationResponse(authrResponse.DATA)

                return { statusCode, responseStruct, responseRaw }
            })
            .then((result) => {
                assert.equal(APDU_STATUS_CODES.SW_NO_ERROR, result.statusCode, 'Authenticator returned an error: ' + result.statusCode);
            })
    })

/* ---------- Negative Tests ---------- */

    it(`F-1

        Send Register command with invalid INS, wrapped in Short APDU, and check that authenticator returns APDU error SW_INS_NOT_SUPPORTED(0x6D00)

    `, () => {
        let frames = [frameAPDUShort(0x00, 0x75, 0x00, 0x00, generateGoodAPDURegisterFrame())];
        return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames)
            .catch((error) => {
                assert.strictEqual(APDU_STATUS_CODES.SW_INS_NOT_SUPPORTED, error.statusCode, `Expected to get SW_INS_NOT_SUPPORTED(0x6D00). Got ${error.statusCodeDef}(${error.statusCode})`);
            })
    })

    it(`F-2

        Send Register command with invalid INS, wrapped in Extended APDU, and check that authenticator returns APDU error SW_INS_NOT_SUPPORTED(0x6D00)

    `, () => {
        let frames = [frameAPDUExtended(0x00, 0x75, 0x00, 0x00, generateGoodAPDURegisterFrame())];
        return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames)
            .catch((error) => {
                assert.strictEqual(APDU_STATUS_CODES.SW_INS_NOT_SUPPORTED, error.statusCode, `Expected to get SW_INS_NOT_SUPPORTED(0x6D00). Got ${error.statusCodeDef}(${error.statusCode})`);
            })
    })

    it(`F-3

        Send Register command wrapped in Short APDU with invalid Lc, and check that authenticator returns APDU error SW_WRONG_LENGTH(0x6700)

    `, () => {
        let frames = [frameAPDUShort(0x00, 0x01, 0x00, 0x00, generateGoodAPDURegisterFrame())];
        frames[0][4] = 0xFF;
        return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames)
            .catch((error) => {
                assert.strictEqual(APDU_STATUS_CODES.SW_WRONG_LENGTH, error.statusCode, `Expected to get SW_WRONG_LENGTH(0x6700). Got ${error.statusCodeDef}(${error.statusCode})`);
            })
    })

    it(`F-4

        Send Register command wrapped in Extended APDU with invalid Lc, and check that authenticator returns APDU error SW_WRONG_LENGTH(0x6700)

    `, () => {
        let frames = [frameAPDUExtended(0x00, 0x01, 0x00, 0x00, generateGoodAPDURegisterFrame())];
        frames[0][6] = 0xFF;
        return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames)
            .catch((error) => {
                assert.strictEqual(APDU_STATUS_CODES.SW_WRONG_LENGTH, error.statusCode, `Expected to get SW_WRONG_LENGTH(0x6700). Got ${error.statusCodeDef}(${error.statusCode})`);
            })
    })
})
