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

        Authr-MakeCred-Req-1

        Test authenticatorMakeCredential(0x01) request MAP

    `, function() {

    before(function() {
        this.timeout(30000);

        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return sendReset()
    })

    after(function() {
        this.timeout(30000);
        return sendReset()
    })

    this.timeout(30000);
    // this.retries(3);

/* ----- POSITIVE TESTS ----- */

    it(`P-1

        Send a valid CTAP2 authenticatorMakeCreditential(0x01) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
            })
    })

/* ----- NEGATIVE TESTS ----- */

    it(`F-1

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "clientDataHash" is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.clientDataHash = undefined;
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-2

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "clientDataHash" is NOT of type BYTE ARRAY, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.clientDataHash = generateRandomTypeExcluding();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-3

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp" is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.rp  = undefined
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-4

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp" is NOT of type MAP, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.rp  = generateRandomTypeExcluding('object');
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-5

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "user" is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct  = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.user = undefined;
        let commandBuffer   = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-6

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "user" is NOT of type MAP, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct  = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.user = generateRandomTypeExcluding('object');
        let commandBuffer   = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-7

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct  = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.pubKeyCredParams = undefined
        let commandBuffer   = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-8

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" is NOT of type ARRAY, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct  = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.pubKeyCredParams = generateRandomTypeExcluding('array')
        let commandBuffer   = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-9

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that is NOT of type SEQUENCE, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct  = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.excludeList = generateRandomTypeExcluding('array')
        let commandBuffer   = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, makeCredStruct.excludeList)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-10

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "extensions" that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct  = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.extensions = generateRandomTypeExcluding('object')
        let commandBuffer   = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, makeCredStruct.extensions)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-11

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "options" that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct  = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.options = generateRandomTypeExcluding('object')
        let commandBuffer   = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, makeCredStruct.options)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })
})