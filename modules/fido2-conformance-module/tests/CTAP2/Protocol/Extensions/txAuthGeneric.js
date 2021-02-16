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

        Authr-Extensions-txAuthGeneric

        Test authenticator support of txAuthGeneric extension

    `, function() {

    let metadata          = window.config.test.metadataStatement
    let rpId              = undefined;
    let origin            = undefined;
    let credId            = undefined;
    let cosePublicKeyBuff = undefined;
    let hashingAlg        = undefined;
    before(function() {
        this.timeout(30000);

        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return sendValidCTAP_CBOR(generateGetInfoRequest())
        .then((ctap2Response) => {
            let cborResponse = ctap2Response.cborResponse;

            let supportedExtensions = cborResponse[GetInfoRespKeys.extensions];
            if(!supportedExtensions || !arrayContainsItem(supportedExtensions, 'txAuthGeneric')) {
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

                let keyStruct = tryDecodeCBORtoJSON(cosePublicKeyBuff);
                hashingAlg    = COSE_ALG_HASH[keyStruct[COSE_KEYS.alg]]
            })
        })
    })

    after(function() {
        this.timeout(30000);
        return sendReset()
    })

    this.timeout(30000);
    // this.retries(3);

    let txAuthGenericArg = {
        'contentType': 'image/png',
        'content': base64url.decode('iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg')
    }

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid GetAssertion request with Extension containing txAuthGeneric extension, and check that authenticator succeeds.

    `, () => {
        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthGeneric': txAuthGenericArg}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendValidCTAP_CBOR(getAssertionBuffer)
    })

    it(`P-2

        Send a valid GetAssertion request with Extension containing txAuthGeneric extension, set to a image, and:
            (a) Decode authData and check that it contains extension data
            (b) Check that extension data contains "txAuthGeneric" key
            (b) Check that extensionData.txAuthGeneric is of type BufferSource
            (c) Check that extensionData.txAuthGeneric value is set to a hash of the content, that is calculated using the same hash function as used for the signature
            (e) Merge authData and clientDataHash, and using previously acquired publicKey verify signature

    `, () => {

        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthGeneric': txAuthGenericArg}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)
        clientDataHash           = goodAssertion.clientDataHash;

        return sendValidCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                let cborGetAssertionResponse       = ctap2Response.cborResponse;
                let cborGetAssertionResponseStruct = ctap2Response.cborResponseStruct;

                let authDataStruct = parseAuthData(cborGetAssertionResponseStruct[GetAssertionRespKeys.authData])

                assert.isTrue(authDataStruct.flags.ed, 'autData is missing ED flag!');
                let extensionsDataStruct = tryDecodeCBORtoJSON(authDataStruct.extensionsData)[0];

                assert.isDefined(extensionsDataStruct.txAuthGeneric, 'Extension data is missing txAuthGeneric!');
                assert.strictEqual(type(extensionsDataStruct.txAuthGeneric) === 'Uint8Array', 'txAuthGeneric extension data must be of type BufferSource!');    

                let contentHash      = navigator.fido.fido2.crypto.hash(hashingAlg, txAuthGenericArg.content);

                assert.strictEqual(hex.encode(contentHash), hex.encode(extensionsDataStruct.txAuthGeneric), 'Extension data does not contains hash of txAuthGenericArg.content!')

                let signatureData    = mergeArrayBuffers(cborGetAssertionResponseStruct[GetAssertionRespKeys.authData], clientDataHash);
                let signature        = cborGetAssertionResponseStruct[GetAssertionRespKeys.signature];

                let signatureIsValid = navigator.fido.fido2.crypto.verifySignatureCOSE(cosePublicKeyBuff, signatureData, signature);
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

        Send a valid GetAssertion request with Extension containing txAuthGeneric extension, with txAuthGenericArg is not of type MAP, and check that authenticator returns an error

    `, () => {
        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthGeneric': generateRandomTypeExcluding('object')}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-2

        Send a valid GetAssertion request with Extension containing txAuthGeneric extension, with txAuthGenericArg.contentType is not of type DOMString, and check that authenticator returns an error

    `, () => {
        let badtxAuthGenericArg  = Object.assign(txAuthGenericArg);
        badtxAuthGenericArg.contentType = generateRandomTypeExcluding('string');

        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthGeneric': badtxAuthGenericArg}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-3

        Send a valid GetAssertion request with Extension containing txAuthGeneric extension, with txAuthGenericArg.contentType is not set to a valid MIME, and check that authenticator returns an error

    `, () => {
        let badtxAuthGenericArg  = Object.assign(txAuthGenericArg);
        badtxAuthGenericArg.contentType = generateRandomString();

        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthGeneric': badtxAuthGenericArg}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-4

        Send a valid GetAssertion request with Extension containing txAuthGeneric extension, with txAuthGenericArg.content is not of type BufferSource, and check that authenticator returns an error

    `, () => {
        let badtxAuthGenericArg  = Object.assign(txAuthGenericArg);
        badtxAuthGenericArg.content = generateRandomTypeExcluding();
        
        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthGeneric': badtxAuthGenericArg}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-5

        Send a valid GetAssertion request with Extension containing txAuthGeneric extension, with txAuthGenericArg.content is set to a BufferSource of a length 0, and check that authenticator returns an error

    `, () => {
        let badtxAuthGenericArg  = Object.assign(txAuthGenericArg);
        badtxAuthGenericArg.content = new Uint8Array();
        
        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthGeneric': badtxAuthGenericArg}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })

    it(`F-6

        Send a valid GetAssertion request with Extension containing txAuthGeneric extension, with txAuthGenericArg.content is set to an invalid byte sequence for a given MIME, and check that authenticator returns an error

    `, () => {
        let badtxAuthGenericArg  = Object.assign(txAuthGenericArg);
        badtxAuthGenericArg.content = generateRandomBuffer(512);
        
        let allowList            = [{ type: 'public-key', id: credId }]
        let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
        let extensions           = {'txAuthGeneric': badtxAuthGenericArg}        
        let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, extensions)

        return sendCTAP_CBOR(getAssertionBuffer)
            .then((ctap2Response) => {
                assert.notStrictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Authenticator succeded when it expected authenticator to fail.`);
            })
    })
})
