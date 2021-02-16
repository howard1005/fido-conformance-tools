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

        Authr-Extensions-txAuthSimple

        Test authenticator support of txAuthSimple extension

    `, function() {

    let metadata          = window.config.test.metadataStatement
    let rpId              = undefined;
    let origin            = undefined;
    let credId            = undefined;
    let cosePublicKeyBuff = undefined;
    before(function() {
        this.timeout(30000);

        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return sendValidCTAP_CBOR(generateGetInfoRequest())
        .then((ctap2Response) => {
            let cborResponse = ctap2Response.cborResponse;

            let supportedExtensions = cborResponse[GetInfoRespKeys.extensions];
            if(!supportedExtensions || !arrayContainsItem(supportedExtensions, 'txAuthSimple')) {
                this.skip();
                return
            }

            let makeCredStruct = generateGoodCTAP2MakeCreditentials();
            let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)
            rpId   = makeCredStruct.rpId;
            origin = makeCredStruct.origin;
            return sendValidCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                let authDataStruct       = parseAuthData(ctap2Response.cborResponseStruct[MakeCredentialsRespKeys.authData]);
                cosePublicKeyBuff        = authDataStruct.COSEPublicKey;
                credId                   = authDataStruct.credId;
            })
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

        Send a valid GetAssertion request with Extension containing txAuthSimple extension, set to a random text, and check that authenticator succeeds.

    `, () => {
        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthSimple': generateRandomTransactionText()}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendValidCTAP_CBOR(getAssertionBuffer)
    })

    it(`P-2

        Send a valid GetAssertion request with Extension containing txAuthSimple extension, set to a random text, and:
            (a) Decode authData and check that it contains extension data
            (b) Check that extension data contains "txAuthSimple" key
            (c) Check that extension data txAuthSimple set to the sent text
            (d) Merge authData and clientDataHash, and using previously acquired publicKey verify signature

    `, () => {

        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthSimple': generateRandomTransactionText()}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)
        clientDataHash           = goodAssertion.clientDataHash;

        return sendValidCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                let cborGetAssertionResponse       = ctap2Response.cborResponse;
                let cborGetAssertionResponseStruct = ctap2Response.cborResponseStruct;

                let authDataStruct = parseAuthData(cborGetAssertionResponseStruct[GetAssertionRespKeys.authData])

                assert.isTrue(authDataStruct.flags.ed, 'autData is missing ED flag!');
                let extensionsDataStruct = tryDecodeCBORtoJSON(authDataStruct.extensionsData)[0];

                assert.isDefined(extensionsDataStruct.txAuthSimple, 'Extension data is missing txAuthSimple!');
                assert.strictEqual(extensionsDataStruct.txAuthSimple, extensions.txAuthSimple, 'Extension.txAuthSimple is not set to the expected value!');

                let signatureData    = mergeArrayBuffers(cborGetAssertionResponseStruct[GetAssertionRespKeys.authData], clientDataHash);
                let signature        = cborGetAssertionResponseStruct[GetAssertionRespKeys.signature];
                let signatureIsValid = navigator.fido.fido2.crypto.verifySignatureCOSE(cosePublicKeyBuff, signatureData, signature)

                assert.isTrue(signatureIsValid, 'The assertion signature can not be verified!');
            })
    })

    it(`P-3

        Check that metadata statement contains txAuthSimple in the list of supported extensions

    `, () => {
        assert.isTrue(metadataContainsExtension('txAuthSimple'), 'Expected Metadata statement to contains txAuthSimple extension in the supportedExtensions list!')
    })

/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send a valid GetAssertion request with Extension containing txAuthSimple extension, not set to a DOMString, and check that authenticator returns an error

    `, () => {
        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthSimple': generateRandomTypeExcluding('string')}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-2

        Send a valid GetAssertion request with Extension containing txAuthSimple extension, set to an empty DOMString, and check that authenticator returns an error

    `, () => {
        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthSimple': ''}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })
})
