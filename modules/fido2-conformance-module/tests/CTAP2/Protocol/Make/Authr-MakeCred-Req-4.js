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

        Authr-MakeCred-Req-4

        Test pubKeyCredParams Sequence in MakeCredential request

    `, function() {

    before(function() {
        this.timeout(30000);

        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')
    })

    after(function() {
        this.timeout(30000);
        return sendReset()
    })

    this.timeout(30000);
    // this.retries(3);

/* ----- POSITIVE TESTS ----- */
/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains an item of type NOT a MAP, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.pubKeyCredParams.push(generateRandomTypeExcluding('object'));
        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-2

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "type" field that is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.pubKeyCredParams[0].type = undefined;
        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-3

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "type" field that is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.pubKeyCredParams[1] = Object.assign({}, makeCredStruct.pubKeyCredParams[0]);
        makeCredStruct.pubKeyCredParams[1].type = generateRandomTypeExcluding('string');
        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-4

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "alg" field is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.pubKeyCredParams[1] = Object.assign({}, makeCredStruct.pubKeyCredParams[0]);
        makeCredStruct.pubKeyCredParams[1].alg = undefined;
        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-5

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "alg" is NOT of type INTEGER, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.pubKeyCredParams[1] = Object.assign({}, makeCredStruct.pubKeyCredParams[0]);
        makeCredStruct.pubKeyCredParams[1].alg = generateRandomTypeExcluding('number');
        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-6

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams", only containing a "PublicKeyCredentialParameters" with "alg" set to unsupported by the authenticator algorithm, wait for the response, and check that Authenticator returns error CTAP2_ERR_UNSUPPORTED_ALGORITHM(0x26).

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.pubKeyCredParams = [
            {
                type: 'public-key',
                alg: 0x45
            }
        ]
        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_UNSUPPORTED_ALGORITHM, `Expected authenticator to fail with CTAP2_ERR_UNSUPPORTED_ALGORITHM(${CTAP_ERROR_CODES.CTAP2_ERR_UNSUPPORTED_ALGORITHM}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`);
            })
    })

    it(`F-7

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "pubKeyCredParams" contains a "PublicKeyCredentialParameters" with "type" is NOT set to "public-key", wait for the response, and check that Authenticator returns error CTAP2_ERR_UNSUPPORTED_ALGORITHM(0x26).

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.pubKeyCredParams = [makeCredStruct.pubKeyCredParams[0]];
        makeCredStruct.pubKeyCredParams[0].type = generateRandomWord();

        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_UNSUPPORTED_ALGORITHM, `Expected authenticator to fail with CTAP2_ERR_UNSUPPORTED_ALGORITHM(${CTAP_ERROR_CODES.CTAP2_ERR_UNSUPPORTED_ALGORITHM}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`);
            })
    })
})
