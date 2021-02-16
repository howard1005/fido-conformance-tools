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

        Authr-GetAssertion-Resp-1.js

        Test GetAssertion response signature

    `, function() {

    let metadata          = window.config.test.metadataStatement
    let cborGetAssertionResponse       = undefined;
    let cborGetAssertionResponseStruct = undefined;
    let rpId              = undefined;
    let origin            = undefined;
    let clientDataHash    = undefined;
    let cosePublicKeyBuff = undefined;
    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)
        rpId   = makeCredStruct.rpId;
        origin = makeCredStruct.origin;
        return sendValidCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                let authDataStruct       = parseAuthData(ctap2Response.cborResponseStruct[MakeCredentialsRespKeys.authData]);
                cosePublicKeyBuff        = authDataStruct.COSEPublicKey;
                let credId               = authDataStruct.credId;
                let allowList            = [{ type: 'public-key', id: credId }]
                let goodAssertion        = generateGoodCTAP2GetAssertion(origin);
                let getAssertionBuffer   = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)
                clientDataHash           = goodAssertion.clientDataHash;

                return sendValidCTAP_CBOR(getAssertionBuffer)
            })
            .then((ctap2Response) => {
                cborGetAssertionResponse       = ctap2Response.cborResponse;
                cborGetAssertionResponseStruct = ctap2Response.cborResponseStruct;
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

        Merge authData and clientDataHash, and using previously acquired publicKey verify signature from GetAssertion_Response

    `, () => {
        let signatureData    = mergeArrayBuffers(cborGetAssertionResponseStruct[GetAssertionRespKeys.authData], clientDataHash);
        let signature        = cborGetAssertionResponseStruct[GetAssertionRespKeys.signature];

        let signatureIsValid = navigator.fido.fido2.crypto.verifySignatureCOSE(cosePublicKeyBuff, signatureData, signature)
        assert.isTrue(signatureIsValid, 'The assertion signature can not be verified!');
    })
})
