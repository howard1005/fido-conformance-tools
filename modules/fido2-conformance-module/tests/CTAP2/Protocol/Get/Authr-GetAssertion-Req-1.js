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

        Authr-GetAssertion-Req-1

        Test getAssertion request

    `, function() {

    let metadata = window.config.test.metadataStatement
    let rpId     = undefined;
    let origin   = undefined;
    let credId   = undefined;
    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        rpId   = makeCredStruct.rpId;
        origin = makeCredStruct.origin;
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendReset()
        .then(() => sendCTAP_CBOR(commandBuffer))
        .then((ctap2Response) => {
            assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);

            let cborMakeCredResponse = ctap2Response.cborResponseStruct;
            let authDataStruct = parseAuthData(cborMakeCredResponse[MakeCredentialsRespKeys.authData]);

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

        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            }
        ]
        let goodAssertion      = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
            })
    })

    it(`F-1

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "rpId" is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            }
        ]
        let goodAssertion      = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(undefined, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-2

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "rpId" is NOT of type STRING, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            }
        ]
        let goodAssertion  = generateGoodCTAP2GetAssertion(origin);
        goodAssertion.rpId = generateRandomTypeExcluding('string');
        let getAssertionBuffer = generateGetAssertionReqCBOR(goodAssertion.rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-3

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "clientDataHash" is missing, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            }
        ]
        let goodAssertion = generateGoodCTAP2GetAssertion(origin);
        goodAssertion.clientDataHash = undefined;
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-4

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "clientDataHash" is NOT of type BYTE ARRAY, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList = [
            {
                type: 'public-key',
                id: credId
            }
        ]
        let goodAssertion  = generateGoodCTAP2GetAssertion(origin);
        goodAssertion.clientDataHash = generateRandomTypeExcluding();
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-5

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" is NOT of type ARRAY, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let allowList      = generateRandomTypeExcluding('array');
        let goodAssertion  = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-6

        Send CTAP2 authenticatorGetAssertion(0x02) message, with "allowList" contains a credential that is NOT of type MAP, wait for the response, and check that Authenticator returns an error.

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
})
