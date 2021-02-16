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

        Authr-MakeCred-Req-6

        Test options in MakeCredential request

    `, function() {

    let metadata                   = window.config.test.metadataStatement
    let options                    = undefined;
    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return sendValidCTAP_CBOR(generateGetInfoRequest())
        .then((ctap2Response) => {
            options = ctap2Response.cborResponse[GetInfoRespKeys.options]
        })
    })

    after(function() {
        this.timeout(30000);

        return sendReset()
    })

    this.timeout(30000);
    this.retries(3)

/* ----- POSITIVE TESTS ----- */

   it(`P-1

        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an unknown option, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let options = {
            'makeTea': true
        }
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);

            })
    })

    it(`P-2

        If authenticator supports "uv" option, send a valid CTAP2 authenticatorMakeCredential(0x01) message, options.uv set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UP flag set

    `, function() {
        if(options && options.uv === true) {
            let makeCredStruct = generateGoodCTAP2MakeCreditentials();
            let options = {
                'uv': true
            }
            let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)

            return sendValidCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                let authDataStruct = parseAuthData(ctap2Response.cborResponseStruct[MakeCredentialsRespKeys.authData]);

                assert.isTrue(authDataStruct.flags.uv, 'Authenticator was given authenticatorMakeCredential(0x01) request with options.uv set to true. Expected authData "uv" flag to be set!');
            })
        } else {
            this.skip();
        }
    })
/* ----- NEGATIVE TESTS ----- */

     it(`F-1

        If authenticator supports "up" option, send a valid CTAP2 authenticatorMakeCredential(0x01) message, options.up set to true, wait for the response, check that Authenticator returns an error CTAP2_ERR_INVALID_OPTION(0x2C)

    `, function() {
        if(!options || options.up === undefined || options.up === true) {
            let makeCredStruct = generateGoodCTAP2MakeCreditentials();
            let options = {
                'up': true
            }
            let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)

            return sendCTAP_CBOR(commandBuffer)
                .then((ctap2Response) => {
                    assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_INVALID_OPTION, `Expected authenticator to succeed with CTAP2_ERR_INVALID_OPTION(${CTAP_ERROR_CODES.CTAP2_ERR_INVALID_OPTION}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`);
                })
        } else {
            this.skip();
        }
    })
})