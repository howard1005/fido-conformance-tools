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

        Authr-MakeCred-Req-5

        Test "excludeList" field in MakeCredential request

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
    this.retries(3);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT set to "public-key", wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.excludeList = [
            {type: 'public-key', id: generateRandomBuffer(32)},
            {type: 'mangoPapayaCoconutIamNotPublicKey', id: generateRandomBuffer(32)}
        ];

        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, makeCredStruct.excludeList)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
            })
    })



/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains an element that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.excludeList = [
            {type: 'public-key', id: generateRandomBuffer(32)},
            generateRandomTypeExcluding('object')
        ];

        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, makeCredStruct.excludeList)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-2

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "type" field is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.excludeList = [
            {type: 'public-key', id: generateRandomBuffer(32)},
            {id: generateRandomBuffer(32)}
        ];

        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, makeCredStruct.excludeList)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-3

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.excludeList = [
            {type: 'public-key', id: generateRandomBuffer(32)},
            {type: generateRandomTypeExcluding('string'), id: generateRandomBuffer(32)}
        ];

        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, makeCredStruct.excludeList)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-5

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "id" field is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.excludeList = [
            {type: 'public-key', id: generateRandomBuffer(32)},
            {type: 'public-key'}
        ];

        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, makeCredStruct.excludeList)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-6

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "id" field is NOT of type ARRAY BUFFER, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.excludeList = [
            {type: 'public-key', id: generateRandomBuffer(32)},
            {type: 'public-key', id: generateRandomTypeExcluding()}
        ];

        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, makeCredStruct.excludeList)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-7

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "excludeList" that contains "PublicKeyCredentialDescriptor" with "id" set to the ID of the previously registered authenticator, wait for the response, and check that Authenticator returns an error CTAP2_ERR_CREDENTIAL_EXCLUDED(0x19).

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        let rp = makeCredStruct.rp;
        console.error("MAKE CREDENTIALS")
        return sendCTAP_CBOR(commandBuffer)
        .then((ctap2Response) => {
            assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);

            let authDataStruct = parseAuthData(ctap2Response.cborResponseStruct[MakeCredentialsRespKeys.authData]);

            let makeCredStruct = generateGoodCTAP2MakeCreditentials();
            makeCredStruct.excludeList = [
                {type: 'public-key', id: authDataStruct.credId}
            ];

            let commandBuffer = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, makeCredStruct.excludeList)

            return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_CREDENTIAL_EXCLUDED, `Expected authenticator to fail with CTAP2_ERR_CREDENTIAL_EXCLUDED(${CTAP_ERROR_CODES.CTAP2_ERR_CREDENTIAL_EXCLUDED}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`);
            })
        })
    })
})
