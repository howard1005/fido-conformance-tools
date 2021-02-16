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

        Authr-MakeCred-Req-2

        Test PublicKeyCredentialRpEntity in MakeCredential request

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

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp.id" is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct   = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.rp.id = generateRandomTypeExcluding('string');
        let commandBuffer    = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-2

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp.name" is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.rp.name = generateRandomTypeExcluding('string');
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-3

        Send CTAP2 authenticatorMakeCredential(0x01) message, with "rp.icon" is NOT of type TEXT, wait for the response, and check that Authenticator returns an error.

    `, () => {
        let makeCredStruct     = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.rp.icon = generateRandomTypeExcluding('string');
        let commandBuffer      = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })
})
