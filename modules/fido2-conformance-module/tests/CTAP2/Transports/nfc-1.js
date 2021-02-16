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

        Test CTAP2 NFC support

    `, function() {

    let deviceInfo = undefined;
    before(function(){
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        deviceInfo = getDeviceInfo();

        if(deviceInfo.transport !== 'NFC')
            this.skip();
    })

    this.timeout(30000);


/* ---------- Positive Tests ---------- */
    it(`P-1

        Send FIDO applet selection command and check that authenticator succeeds.

            For CTAP1(U2F) compatible authenticators check that authenticator returns 0x5532465F5632(U2F_V2) in response.
            For CTAP2 only authenticators check that authenticator returns 0x4649444f5f325f30(FIDO_2_0) in response.

    `, () => {
        let appletSelectionCommand = new Uint8Array([0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00]);
        return navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), [appletSelectionCommand], true)
            .then((response) => {
                let u2fCompatible = confirm('Is your device U2F compatible?');

                if(u2fCompatible && hex.encode(response[0]) !== '5532465f56329000')
                    throw new Error('For U2F compatible CTAP2 authenticators it MUST return legacy "U2F_V2" string!');
                else if(!u2fCompatible && hex.encode(response[0]) !== '4649444f5f325f309000')
                    throw new Error('For CTAP2 only authenticators, it MUST return FIDO_2_0 string!');
            })
    })

    it(`P-2

        Send a valid CTAP2 authenticatorMakeCreditential(0x01) message, wrapped in Extended APDU, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendExtendedCTAPNFC_CBORCommand(commandBuffer)
            .then((response) => {
                return parseCTAP2Response(response)
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
            })
    })

    it(`P-3

        Send a valid CTAP2 authenticatorMakeCreditential(0x01) message, wrapped in Short APDU, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendShortCTAPNFC_CBORCommand(commandBuffer)
            .then((response) => {
                return parseCTAP2Response(response)
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
            })
    })

    it(`P-4

        Send a valid CTAP2 authenticatorMakeCreditential(0x01) message, wrapped in Short APDU with mixed sizes, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

    `, () => {

        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        let frames = generateRandomlySizedShortAPDUCTAP2Frames(commandBuffer)
        return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames)
            .then((result) => {
                let base = new Uint8Array();

                for(let buff of result)
                    base = mergeArrayBuffers(base, buff)

                return base
            })
            .then((response) => {
                response = response.slice(0, response.length - 2);
                return parseCTAP2Response(response)
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
            })
    })

/* ---------- Negative Tests ---------- */

    it(`F-1

        Send CTAP2 getInfo(0x04) with invalid INS, wrapped in Short APDU, and check that authenticator returns APDU error SW_INS_NOT_SUPPORTED(0x6D00)

    `, () => {
        let frames = [frameAPDUShort(0x80, 0x75, 0x00, 0x00, generateGetInfoRequest())];
        return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames)
            .catch((error) => {
                assert.strictEqual(APDU_STATUS_CODES.SW_INS_NOT_SUPPORTED, error.statusCode, `Expected to get SW_INS_NOT_SUPPORTED(0x6D00). Got ${error.statusCodeDef}(${error.statusCode})`);
            })
    })

    it(`F-2

        Send CTAP2 getInfo(0x04) with invalid INS, wrapped in Extended APDU, and check that authenticator returns APDU error SW_INS_NOT_SUPPORTED(0x6D00)

    `, () => {
        let frames = [frameAPDUExtended(0x80, 0x75, 0x00, 0x00, generateGetInfoRequest())];
        return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames)
            .catch((error) => {
                assert.strictEqual(APDU_STATUS_CODES.SW_INS_NOT_SUPPORTED, error.statusCode, `Expected to get SW_INS_NOT_SUPPORTED(0x6D00). Got ${error.statusCodeDef}(${error.statusCode})`);
            })
    })

    it(`F-3

        Send CTAP2 getInfo(0x04) wrapped in Short APDU with invalid Lc, and check that authenticator returns APDU error SW_WRONG_LENGTH(0x6700)

    `, () => {
        let frames = [frameAPDUShort(0x80, 0x10, 0x00, 0x00, generateGetInfoRequest())];
        frames[0][4] = 0xFF;
        return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames)
            .catch((error) => {
                assert.strictEqual(APDU_STATUS_CODES.SW_WRONG_LENGTH, error.statusCode, `Expected to get SW_WRONG_LENGTH(0x6700). Got ${error.statusCodeDef}(${error.statusCode})`);
            })
    })

    it(`F-4

        Send CTAP2 getInfo(0x04) wrapped in Extended APDU with invalid Lc, and check that authenticator returns APDU error SW_WRONG_LENGTH(0x6700)

    `, () => {
        let frames = [frameAPDUExtended(0x80, 0x10, 0x00, 0x00, generateGetInfoRequest())];
        frames[0][6] = 0xFF;
        return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames)
            .catch((error) => {
                assert.strictEqual(APDU_STATUS_CODES.SW_WRONG_LENGTH, error.statusCode, `Expected to get SW_WRONG_LENGTH(0x6700). Got ${error.statusCodeDef}(${error.statusCode})`);
            })
    })
})
