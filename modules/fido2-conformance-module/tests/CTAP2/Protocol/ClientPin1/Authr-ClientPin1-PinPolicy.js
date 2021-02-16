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

        Authr-ClientPin1-Policy

        Check authenticator correctly implementing PinProtocol security policies

    `, function() {

    before(function() {
        this.timeout(30000);

        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return sendCTAP_CBOR(generateGetInfoRequest(), {'dontResetCard': true})
            .then((response) => {
                let pinProtocols = response.cborResponse[GetInfoRespKeys.pinProtocols];

                if(!pinProtocols || !arrayContainsItem(pinProtocols, 0x01)) {
                    this.skip()
                } else {
                    return sendReset()
                }
            })
    })

    beforeEach(function() {
        this.timeout(30000);
        return sendReset()
    })

    this.timeout(60000);
    // this.retries(3);

/* ----- POSITIVE TESTS ----- */

    it(`P-1

        Try setting new pin, that is of size between 5 and 63 characters, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00)

    `, () => {
        let pinBuffer = generateRandomClientPinBuffer(generateSecureRandomInt(5, 63));
        let commandBuffer = generateClientPin_GetKeyAgreement();
        return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            .then((response) => {
                let cborResponse       = response.cborResponse;
                let cborResponseStruct = response.cborResponseStruct;

                assert.isDefined(cborResponse[ClientPinRespKeys.keyAgreement], 'authenticatorClientPin_Response missing "keyAgreement" field!');
                assert.isObject(cborResponse[ClientPinRespKeys.keyAgreement], 'authenticatorClientPin_Response.keyAgreement MUST be of type MAP');

                let keyStruct = cborResponse[ClientPinRespKeys.keyAgreement];
                let keyBuffer = COSEECDHAtoPKCS(keyStruct);

                let platformPrivateKey = window.navigator.fido.fido2.crypto.generateP256DHKeys().private;
                let platformPublicKey  = window.navigator.fido.fido2.crypto.deriveP256DHPublicKey(platformPrivateKey)
                
                let sharedSecretPKXCoefficient = window.navigator.fido.fido2.crypto.deriveP256DHSecretsXCoefficient(platformPrivateKey, keyBuffer);
                let sharedSecret = window.navigator.fido.fido2.crypto.hash('sha256', sharedSecretPKXCoefficient);

                let encryptionBuffer = generateZeroBuffer(64);
                encryptionBuffer.set(pinBuffer);

                let newPinEnc     = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(sharedSecret, encryptionBuffer);
                let newPinEncHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(sharedSecret, newPinEnc);
                let pinAuth       = newPinEncHMAC.slice(0, 16);

                let platPKXCoeff = platformPublicKey.slice(1,33);
                let platPKYCoeff = platformPublicKey.slice(33);

                let keyAgreement = {
                     '1': 2,
                    '-1': 1,
                    '3': -25,
                    '-2': platPKXCoeff,
                    '-3': platPKYCoeff
                }

                let commandBuffer = generateClientPin_SetPIN({
                    pinAuth, newPinEnc, keyAgreement
                })

                return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
            })
    })

    it(`F-1

        Try setting new pin, that is less than 4 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION(0x37)

    `, () => {
        let pinBuffer = generateRandomClientPinBuffer(generateSecureRandomInt(1, 3));
        let commandBuffer = generateClientPin_GetKeyAgreement();
        return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            .then((response) => {
                let cborResponse       = response.cborResponse;
                let cborResponseStruct = response.cborResponseStruct;

                assert.isDefined(cborResponse[ClientPinRespKeys.keyAgreement], 'authenticatorClientPin_Response missing "keyAgreement" field!');
                assert.isObject(cborResponse[ClientPinRespKeys.keyAgreement], 'authenticatorClientPin_Response.keyAgreement MUST be of type MAP');

                let keyStruct = cborResponse[ClientPinRespKeys.keyAgreement];
                let keyBuffer = COSEECDHAtoPKCS(keyStruct);

                let platformPrivateKey = window.navigator.fido.fido2.crypto.generateP256DHKeys().private;
                let platformPublicKey  = window.navigator.fido.fido2.crypto.deriveP256DHPublicKey(platformPrivateKey)
                
                let sharedSecretPKXCoefficient = window.navigator.fido.fido2.crypto.deriveP256DHSecretsXCoefficient(platformPrivateKey, keyBuffer);
                let sharedSecret = window.navigator.fido.fido2.crypto.hash('sha256', sharedSecretPKXCoefficient);

                let encryptionBuffer = generateZeroBuffer(64);
                encryptionBuffer.set(pinBuffer);

                let newPinEnc     = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(sharedSecret, encryptionBuffer);
                let newPinEncHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(sharedSecret, newPinEnc);
                let pinAuth       = newPinEncHMAC.slice(0, 16);

                let platPKXCoeff = platformPublicKey.slice(1,33);
                let platPKYCoeff = platformPublicKey.slice(33);

                let keyAgreement = {
                     '1': 2,
                    '-1': 1,
                    '3': -25,
                    '-2': platPKXCoeff,
                    '-3': platPKYCoeff
                }

                let commandBuffer = generateClientPin_SetPIN({
                    pinAuth, newPinEnc, keyAgreement
                })

                return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_PIN_POLICY_VIOLATION, `Expected authenticator to fail with CTAP2_ERR_PIN_POLICY_VIOLATION(${CTAP_ERROR_CODES.CTAP2_ERR_PIN_POLICY_VIOLATION}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`);
            })
    })

    it(`F-2

        Try setting new pin, that is bigger than 63 bytes, and check that Authenticator returns error CTAP2_ERR_PIN_POLICY_VIOLATION(0x37)

    `, () => {
        let pinBuffer = generateRandomClientPinBuffer(64);
        let commandBuffer = generateClientPin_GetKeyAgreement();
        return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            .then((response) => {
                let cborResponse       = response.cborResponse;
                let cborResponseStruct = response.cborResponseStruct;

                assert.isDefined(cborResponse[ClientPinRespKeys.keyAgreement], 'authenticatorClientPin_Response missing "keyAgreement" field!');
                assert.isObject(cborResponse[ClientPinRespKeys.keyAgreement], 'authenticatorClientPin_Response.keyAgreement MUST be of type MAP');

                let keyStruct = cborResponse[ClientPinRespKeys.keyAgreement];
                let keyBuffer = COSEECDHAtoPKCS(keyStruct);

                let platformPrivateKey = window.navigator.fido.fido2.crypto.generateP256DHKeys().private;
                let platformPublicKey  = window.navigator.fido.fido2.crypto.deriveP256DHPublicKey(platformPrivateKey)
                
                let sharedSecretPKXCoefficient = window.navigator.fido.fido2.crypto.deriveP256DHSecretsXCoefficient(platformPrivateKey, keyBuffer);
                let sharedSecret = window.navigator.fido.fido2.crypto.hash('sha256', sharedSecretPKXCoefficient);

                let encryptionBuffer = generateZeroBuffer(64);
                encryptionBuffer.set(pinBuffer);

                let newPinEnc     = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(sharedSecret, encryptionBuffer);
                let newPinEncHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(sharedSecret, newPinEnc);
                let pinAuth       = newPinEncHMAC.slice(0, 16);

                let platPKXCoeff = platformPublicKey.slice(1,33);
                let platPKYCoeff = platformPublicKey.slice(33);

                let keyAgreement = {
                     '1': 2,
                    '-1': 1,
                    '3': -25,
                    '-2': platPKXCoeff,
                    '-3': platPKYCoeff
                }

                let commandBuffer = generateClientPin_SetPIN({
                    pinAuth, newPinEnc, keyAgreement
                })

                return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP2_ERR_PIN_POLICY_VIOLATION, `Expected authenticator to fail with CTAP2_ERR_PIN_POLICY_VIOLATION(${CTAP_ERROR_CODES.CTAP2_ERR_PIN_POLICY_VIOLATION}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`);
            })
    })
})
