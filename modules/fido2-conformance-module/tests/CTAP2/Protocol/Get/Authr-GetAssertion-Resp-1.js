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

        Test GetAssertion response

    `, function() {

    let metadata = window.config.test.metadataStatement
    let cborGetAssertionResponse       = undefined;
    let cborGetAssertionResponseStruct = undefined;
    let credId   = undefined;
    let rpId     = undefined;
    let origin   = undefined;
    let rpIdHash = undefined;
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
                let authDataStruct = parseAuthData(ctap2Response.cborResponseStruct[MakeCredentialsRespKeys.authData]);

                credId = authDataStruct.credId;

                let allowList = [
                    {
                        type: 'public-key',
                        id: credId
                    }
                ]
                let goodAssertion = generateGoodCTAP2GetAssertion(origin);
                let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)
                rpIdHash = window.navigator.fido.fido2.crypto.hash('sha256', rpId);
                
                return sendValidCTAP_CBOR(getAssertionBuffer)
            })
            .then((ctap2Response) => {
                cborGetAssertionResponse = ctap2Response.cborResponse;
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

        Parse GetAssertion response, and check that:
            (a) response includes "signature" field, and it's of type BYTE STRING
            (b) response includes "authData" field, and it's of type BYTE STRING
            (c) response MUST not include "user", "credential" and "numberOfCredentials"

    `, () => {
        assert.isDefined(cborGetAssertionResponse[GetAssertionRespKeys.signature], 'GetAssertion_Response is missing "signature" field!');
        assert.strictEqual(type(cborGetAssertionResponseStruct[GetAssertionRespKeys.signature]), 'Uint8Array', 'GetAssertion_Response.signature MUST be of type BYTE STRING!')
        assert.isDefined(cborGetAssertionResponse[GetAssertionRespKeys.authData], 'GetAssertion_Response is missing "authData" field!');
        assert.strictEqual(type(cborGetAssertionResponseStruct[GetAssertionRespKeys.authData]), 'Uint8Array', 'GetAssertion_Response.authData MUST be of type BYTE STRING!')
    })

    it(`P-2

        Parse GetAssertion_Response.authData and:
            (a) Check that it's exactly 37 bytes long
            (b) Check that authData.rpIdHash matches the hash of the GetAssertion_Request.rpId
            (c) Check that AT flag in authData.flags bitmap is not set

    `, () => {
        assert.strictEqual(cborGetAssertionResponseStruct[GetAssertionRespKeys.authData].byteLength, 37, 'GetAssertion_Response.authData MUST be exactly 37 bytes long(32(rpIdHash) + 1(flags) + 4(counter)!');
        let authDataStruct = parseAuthData(cborGetAssertionResponseStruct[GetAssertionRespKeys.authData]);
        assert.strictEqual(hex.encode(authDataStruct.rpIdHash), hex.encode(rpIdHash), 'authData.rpIdHash does not match rpIdHash!');
        assert.isFalse(authDataStruct.flags.at, 'AT flag in authData.flags bitmap MUST NOT be set!');
    })

    it(`P-3

        Send three valid CTAP2 authenticatorGetAssertion(0x02) request, wait for the responses, and check that response2.counter is bigger than response1.counter, and response3.counter is bigger than response2.counter.

    `, () => {
        let counterA = undefined;
        let counterB = undefined;
        let counterC = undefined;

        let getCounterValue = () => {
            let allowList = [{ type: 'public-key', id: credId }]
            let goodAssertion = generateGoodCTAP2GetAssertion(origin);
            let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

            return sendValidCTAP_CBOR(getAssertionBuffer)
                .then((ctap2Response) => {
                    let authDataStruct = parseAuthData(ctap2Response.cborResponseStruct[GetAssertionRespKeys.authData]);
                    return authDataStruct.counter
                })
        }

        return getCounterValue()
            .then((counter) => {
                counterA = counter;
                return getCounterValue()
            })
            .then((counter) => {
                counterB = counter;
                return getCounterValue()
            })
            .then((counter) => {
                counterC = counter;

                assert.isTrue(counterA < counterB, `Authenticator was sent three GetAssertion requests. Counter was NOT increased. Expected A(${counterA}) < B(${counterB})!`);
                assert.isTrue(counterB < counterC, `Authenticator was sent three GetAssertion requests. Counter was NOT increased. Expected B(${counterB}) < C(${counterC})!`);
            })
    })
})


