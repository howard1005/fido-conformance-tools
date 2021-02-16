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

        Authr-Reset-1

        Test authenticator support of Reset command

    `, function() {

    this.timeout(30000);
    // this.retries(3);
    
/* ----- POSITIVE TESTS ----- */

    it(`P-1

        Successfully executy makeCredential, and test it by sending consequent getAssertion and check that both are succeeding.

        Send authenticatorReset(0x07) immidietly after, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with credId from the previously registered makeCredential, wait for the response, and check that Authenticator returns CTAP2_ERR_NO_CREDENTIALS(0x2E) error code.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        rpId   = makeCredStruct.rpId;
        origin = makeCredStruct.origin;
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)
        let credId = undefined;

        return sendValidCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                let authDataStruct = parseAuthData(ctap2Response.cborResponseStruct[MakeCredentialsRespKeys.authData]);

                credId = authDataStruct.credId;

                let allowList          = [{ type: 'public-key', id: credId }];
                let goodAssertion      = generateGoodCTAP2GetAssertion(origin);
                let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)
                return sendValidCTAP_CBOR(getAssertionBuffer)
            })
            .then(() => {
                if(getDeviceInfo().transport === 'HID')
                    alert('If your device requires power reset before sending reset, please unplug you device and plug it back in, otherwise please press enter.');
                
                return sendValidCTAP_CBOR(generateResetRequest())
            })
            .then(() => {
                let allowList          = [{ type: 'public-key', id: credId }];
                let goodAssertion      = generateGoodCTAP2GetAssertion(origin);
                let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)
                return sendCTAP_CBOR(getAssertionBuffer)
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_NO_CREDENTIALS, `Expected authenticator to fail with CTAP2_ERR_NO_CREDENTIALS(${CTAP_ERROR_CODES.CTAP2_ERR_NO_CREDENTIALS}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`)
            })
    })
})