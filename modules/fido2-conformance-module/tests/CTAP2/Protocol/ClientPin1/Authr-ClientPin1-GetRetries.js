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

        Authr-ClientPin1-GetRetries

        Test authenticatorClientPin(0x06), of version 0x01 support of getRetries(0x01) command

    `, function() {

    let pincode = '123456';
    before(function() {
        this.timeout(30000);

        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return sendCTAP_CBOR(generateGetInfoRequest())
            .then((response) => {
                let pinProtocols = response.cborResponse[GetInfoRespKeys.pinProtocols];
                pincode = leftpad(generateSecureRandomInt(0, 100000000), 6);

                if(!pinProtocols || !arrayContainsItem(pinProtocols, 0x01)) {
                    this.skip()
                } else {
                    return sendReset()
                        .then(() => {
                            return setNewPincode(pincode)
                        })
                }
            })
    })

    after(function() {
        this.timeout(30000);
        return sendReset()
    })

    this.timeout(60000);
    // this.retries(3);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid CTAP2 authenticatorClientPin(0x01) message with getRetries(0x01) subCommand, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) check that authenticatorClientPin_Response contains "retries" field
            (b) authenticatorClientPin_Response.retries is of type NUMBER
            (c) authenticatorClientPin_Response.retries is extractly 8

    `, () => {
        let commandBuffer = generateClientPin_GetRetries();
        return sendValidCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            .then((ctap2Response) => {
                let cborResponse = ctap2Response.cborResponse;

                let retries = cborResponse[ClientPinRespKeys.retries];

                assert.isDefined(retries, 'Response is missing "retries(0x03)" field!');
                assert.isNumber(retries, 'Retries MUST be of type NUMBER!');
                assert.strictEqual(retries, 8, 'Retries MUST be set to 8!');
            })
    })

    it(`P-2

        Send two CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains invalid pinCode, and check that each request fails with error CTAP2_ERR_PIN_INVALID(0x31)
        
        Send a valid CTAP2 authenticatorClientPin(0x01) message with getRetries(0x01) subCommand, and check that retries have decreased by two

        Send CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains invalid pinCode, and check that authenticator returns CTAP2_ERR_PIN_AUTH_BLOCKED(0x34)

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, undefined, generateRandomBuffer(16), 0x01);
        return getPINTokenRaw(generateRandomName())
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_PIN_INVALID, `Expected authenticator to succeed with CTAP2_ERR_PIN_INVALID(${CTAP_ERROR_CODES.CTAP2_ERR_PIN_INVALID}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`)
            })
            .then(() => {
                return getPINTokenRaw(generateRandomName())
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_PIN_INVALID, `Expected authenticator to succeed with CTAP2_ERR_PIN_INVALID(${CTAP_ERROR_CODES.CTAP2_ERR_PIN_INVALID}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`)
                return sendValidCTAP_CBOR(generateClientPin_GetRetries(), undefined, true)
            })
            .then((ctap2Response) => {
                let cborResponse = ctap2Response.cborResponse;

                let retries = cborResponse[ClientPinRespKeys.retries];

                assert.isDefined(retries, 'Response is missing retries(0x03) field!');
                assert.isNumber(retries, 'Retries MUST be of type NUMBER!');
                assert.strictEqual(retries, 6, 'Retries MUST be set to 8!');
                return getPINTokenRaw(generateRandomName())
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_PIN_AUTH_BLOCKED, `Expected authenticator to succeed with CTAP2_ERR_PIN_AUTH_BLOCKED(${CTAP_ERROR_CODES.CTAP2_ERR_PIN_AUTH_BLOCKED}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`)
            })
    })

    it(`P-3
        
        Register a valid authenticatorMakeCred(0x01) using the valid PIN. Check that retries counter is reset and back to 8.

        Keep sending getPINToken with invalid pin until retries counter is 0.

        Send CTAP2 authenticatorClientPin(0x01) message with getPinToken(0x01) subCommand, that contains valid pinCode, and check that authenticator returns error CTAP2_ERR_PIN_BLOCKED(0x32)

    `, function() {
        this.timeout(60000)

        alert('Please unplug you device and plug it back in!');

        let retries = 0;
        let credId  = undefined;
        let wasPinAuthBlocked = false;
        let sendBadPinRequest = () => {
            retries--;

            return getPINTokenRaw(generateRandomName())
                .then((ctap2Response) => {
                    if(ctap2Response.statusCode === CTAP_ERROR_CODES.CTAP2_ERR_PIN_AUTH_BLOCKED) {
                        if(wasPinAuthBlocked)
                            retries++
                        else
                            wasPinAuthBlocked = true;

                        alert('Please unplug you device and plug it back in!')
                    } else if(ctap2Response.statusCode !== CTAP_ERROR_CODES.CTAP2_ERR_PIN_INVALID && (ctap2Response.statusCode !== CTAP_ERROR_CODES.CTAP2_ERR_PIN_BLOCKED && retries > 0)) {
                        throw new Error(`Expected authenticator to succeed with CTAP2_ERR_PIN_INVALID(${CTAP_ERROR_CODES.CTAP2_ERR_PIN_INVALID}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`)
                    } else {
                        wasPinAuthBlocked = false;
                    }

                    if(retries !== 0)
                        return nfcResetFix()
                            .then(() => sendBadPinRequest())
                })
        }

        let nfcResetFix = () => {
            if(getDeviceInfo().transport === 'NFC') {
                return TimeoutPromise(200)
                    .then(() => navigator.fido.fido2.nfc.forceResetCard(getDeviceInfo()))
            } else
                return Promise.resolve()
        }

        return TimeoutPromise(200)
            .then(() => nfcResetFix())
            .then(() => getPINToken(pincode))
            .then((pinToken) => {
                let makeCredStruct = generateGoodCTAP2MakeCreditentials();
                rpId = makeCredStruct.rp.id;

                let pinHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(pinToken, makeCredStruct.clientDataHash);
                let pinAuth = pinHMAC.slice(0, 16);

                let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, undefined, pinAuth, 0x01);

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((ctap2Response) => {
                return getRetries()
            })
            .then((newRetries) => {
                assert.strictEqual(newRetries, 8, 'After successull pin auth, retries counter MUST be reset back to 8!');

                retries = newRetries
                return sendBadPinRequest()
            })
            .then(() => {
                return getPINTokenRaw(pincode)
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_PIN_BLOCKED, `Expected authenticator to fail with CTAP2_ERR_PIN_BLOCKED(${CTAP_ERROR_CODES.CTAP2_ERR_PIN_BLOCKED}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`)
            })
    })
})

