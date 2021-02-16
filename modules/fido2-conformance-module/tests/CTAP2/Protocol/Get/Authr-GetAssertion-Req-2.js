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

        Authr-GetAssertion-Req-2

        Test "options" in GetAssertion request

    `, function() {

    let metadata = window.config.test.metadataStatement
    let credId   = undefined;
    let rpId     = undefined;
    let origin   = undefined;
    let options  = undefined;
    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)
        rpId   = makeCredStruct.rpId;
        origin = makeCredStruct.origin;
        return sendValidCTAP_CBOR(generateGetInfoRequest())
            .then((ctap2Response) => {
                let cborResponse = ctap2Response.cborResponse;
                options = cborResponse[GetInfoRespKeys.options]

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((ctap2Response) => {
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

        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, "options" containg an unknown option, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

    `, () => {
        let allowList = [{ type: 'public-key', id: credId }];
        let options = {
            'makeTea': true
        }
        let goodAssertion = generateGoodCTAP2GetAssertion(origin);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, undefined, options)

        return sendValidCTAP_CBOR(getAssertionBuffer)
    })

    it(`P-2

        If authenticator supports "up" option, send a valid CTAP2 authenticatorGetAssertion(0x02) message, options.up set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UP flag set

    `, function() {
        if(!options || options.up === undefined || options.up === true) {
            let allowList = [{ type: 'public-key', id: credId }];
            let options = {
                'up': true
            }
            let goodAssertion = generateGoodCTAP2GetAssertion(origin);
            let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, undefined, options)

            return sendValidCTAP_CBOR(getAssertionBuffer)
                .then((ctap2Response) => {
                    let authDataStruct = parseAuthData(ctap2Response.cborResponseStruct[GetAssertionRespKeys.authData]);

                    assert.isTrue(authDataStruct.flags.up, 'Authenticator was given authenticatorGetAssertion(0x02) request with options.up set to true. Expected authData "up" flag to be set!');
                })
        } else {
            this.skip();
        }
    })

    it(`P-3

        If authenticator supports "uv" option, send a valid CTAP2 authenticatorGetAssertion(0x02) message, options.uv set to true, wait for the response, check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and check that authenticatorData.flags have UV flag set

    `, function() {
        if(options && options.uv === true) {
            let allowList = [{ type: 'public-key', id: credId }];
            let options = {
                'uv': true
            }
            let goodAssertion = generateGoodCTAP2GetAssertion(origin);
            let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, undefined, options)

            return sendValidCTAP_CBOR(getAssertionBuffer)
                .then((ctap2Response) => {
                    let authDataStruct = parseAuthData(ctap2Response.cborResponseStruct[GetAssertionRespKeys.authData]);

                    assert.isTrue(authDataStruct.flags.uv, 'Authenticator was given authenticatorGetAssertion(0x02) request with options.uv set to true. Expected authData "uv" flag to be set!');
                })
        } else {
            this.skip();
        }
    })
})