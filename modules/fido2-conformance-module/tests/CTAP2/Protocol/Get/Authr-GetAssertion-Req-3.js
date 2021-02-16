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

        Authr-GetAssertion-Req-3

        Test "allowList" field in MakeCredential request

    `, function() {

    let metadata = window.config.test.metadataStatement
    let credId   = undefined;
    let origin   = undefined;
    let rpId     = undefined;
    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)
        rpId   = makeCredStruct.rpId;
        origin = makeCredStruct.origin;
        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);

                let authDataStruct = parseAuthData(ctap2Response.cborResponseStruct[MakeCredentialsRespKeys.authData]);

                credId = authDataStruct.credId;
            })
    })

    after(function() {
        this.timeout(30000);
        return sendReset()
    })

    this.timeout(30000);
    // this.retries(3);

/* ----- POSITIVE TESTS ----- */  
    it(`P-1

        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT set to "public-key", wait for the response, and check that authenticator returns CTAP1_ERR_SUCCESS(0x00) error code

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            },
            {
                type: 'queen-elisabeth-the-second',
                id: generateRandomBuffer(32)
            }
        ]
        let goodAssertion      = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendValidCTAP_CBOR(getAssertionBuffer)
    })  

/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains an element that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            },
            generateRandomTypeExcluding('object')
        ]
        let goodAssertion  = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-2

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "type" field is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            },
            {
                id: generateRandomBuffer(32)
            }
        ]
        let goodAssertion  = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-3

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "type" field is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            },
            {
                type: generateRandomTypeExcluding('string'),
                id: generateRandomBuffer(32)
            }
        ]
        let goodAssertion  = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-4

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "id" field is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            },
            {
                type: 'public-key'
            }
        ]
        let goodAssertion  = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-5

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" that contains "PublicKeyCredentialDescriptor" with "id" field is NOT of type ARRAY BUFFER, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            },
            {
                type: 'public-key',
                id: generateRandomTypeExcluding()
            }
        ]
        let goodAssertion  = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })


    it(`F-6

        If authenticator is Second-Factor only: Send CTAP2 authenticatorGetAssertion(0x02) message, with missing "allowList", and check that authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E) error code.

    `, function() {
        if(metadata.isSecondFactorOnly) {
            let goodAssertion  = generateGoodCTAP2GetAssertion(origin);
            let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash)

            return sendCTAP_CBOR(getAssertionBuffer)
                .then((ctap2Response) => {
                    assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_NO_CREDENTIALS, `Expected authenticator to fail with CTAP2_ERR_NO_CREDENTIALS(${CTAP_ERROR_CODES.CTAP2_ERR_NO_CREDENTIALS}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`);
                })
        } else {
            this.skip();
        }
    })
})
