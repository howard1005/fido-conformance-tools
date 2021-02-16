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

        Authr-ClientPin1-NewPin

        Test authenticatorClientPin(0x06), of version 0x01 support of setPIN(0x03), changePIN(0x04) and getPINToken(0x05) commands

    `, function() {

    let pincode         = '123456';
    let clientPinIsOkay = false;
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
                pincode = leftpad(generateSecureRandomInt(0, 100000000), 6);
                return sendReset()
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

        Generate a shared key by deriving sharedSecret from previously obtained keyAgreement, and set new random clientPin

    `, () => {
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
                let pinBuffer        = UTF8toBuffer(pincode);
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

                clientPinIsOkay = ctap2Response.statusCode === CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS
            })
    })

    it(`P-2

        Change current pincode to the new pincode

    `, () => {
        if(!clientPinIsOkay)
            throw new Error('Can not run test because P-1 have failed!');

        let newPincode    = leftpad(generateSecureRandomInt(0, 100000000), 8);
        let commandBuffer = generateClientPin_GetKeyAgreement();
        return establishKeyAgreement()
            .then((response) => {
                /* pinHashEnc */
                let currentPinBuffer     = UTF8toBuffer(pincode);
                let currentPinBufferHash = window.navigator.fido.fido2.crypto.hash('sha256', currentPinBuffer);
                let pinHashEnc           = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(response.sharedSecret, currentPinBufferHash.slice(0, 16));

                /* newPinEnc */
                let newPincodeBuffer = UTF8toBuffer(newPincode);
                let encryptionBuffer = generateZeroBuffer(64);
                encryptionBuffer.set(newPincodeBuffer);
                let newPinEnc     = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(response.sharedSecret, encryptionBuffer);

                /* pinAuth */
                let newOldPinEncHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(response.sharedSecret, mergeArrayBuffers(newPinEnc, pinHashEnc));
                let pinAuth       = newOldPinEncHMAC.slice(0, 16);

                let keyAgreement  = response.keyAgreement;
                let commandBuffer = generateClientPin_ChangePIN({
                    pinHashEnc, newPinEnc, pinAuth, keyAgreement
                })

                return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);

                clientPinIsOkay = ctap2Response.statusCode === CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS

                if(clientPinIsOkay) {
                    pincode = newPincode;
                }
            })
    })

    it(`P-3

        Get a valid pinAuth token

    `, () => {
        if(!clientPinIsOkay)
            throw new Error('Can not run test because P-1 or P-2 have failed!');

        let sharedSecret = undefined;
        return establishKeyAgreement()
            .then((response) => {
                sharedSecret              = response.sharedSecret;
                let pinCodeBuffer         = UTF8toBuffer(pincode);
                let pinCodeHashBuffer     = window.navigator.fido.fido2.crypto.hash('sha256', pinCodeBuffer);
                let pinCodeHashBufferLEFT = pinCodeHashBuffer.slice(0, 16);

                let pinHashEnc   = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(sharedSecret, pinCodeHashBufferLEFT);
                let keyAgreement = response.keyAgreement;

                let commandBuffer = generateClientPin_GetPINToken({pinHashEnc, keyAgreement})

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((response) => {
                let pinToken = response.cborResponseStruct[ClientPinRespKeys.pinToken];
                let decryptedToken = window.navigator.fido.fido2.crypto.decryptAES256CBCIV0(sharedSecret, pinToken);
            })
    })

    let rpId   = undefined;
    let origin = undefined;
    let credId = undefined;
    it(`P-4

        Send a valid CTAP2 authenticatorMakeCreditential(0x01) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

        Check that authData.flags have UV flag set

    `, () => {
        if(!clientPinIsOkay)
            throw new Error('Can not run test because P-1, P-2 or P-3 have failed!');

        return getPINToken(pincode)
            .then((pinToken) => {
                let makeCredStruct = generateGoodCTAP2MakeCreditentials();
                rpId   = makeCredStruct.rpId;
                origin = makeCredStruct.origin;
                let pinHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(pinToken, makeCredStruct.clientDataHash);
                let pinAuth = pinHMAC.slice(0, 16);

                let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, undefined, pinAuth, 0x01);

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((ctap2Response) => {
                let cborMakeCredResponse = ctap2Response.cborResponseStruct;
                let authDataStruct = parseAuthData(cborMakeCredResponse[MakeCredentialsRespKeys.authData]);

                assert.isTrue(authDataStruct.flags.uv, 'For CTAP2 request that is done with user verification using pin, UV flag MUST be set to true!');

                credId = authDataStruct.credId;
            })
    })

    it(`P-5

        Send a valid CTAP2 authenticatorGetAssertion(0x02) message with pinAuth, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

        Check that authData.flags have UV flag set

    `, () => {
        if(!credId)
            throw new Error('Can not run test because P-4 have failed!');

        return getPINToken(pincode)
            .then((pinToken) => {

                let allowList = [{type: 'public-key', id: credId}]
                let goodAssertion = generateGoodCTAP2GetAssertion(origin);

                let pinHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(pinToken, goodAssertion.clientDataHash);
                let pinAuth = pinHMAC.slice(0, 16);

                let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList, undefined, undefined, pinAuth, 0x01)

                return sendValidCTAP_CBOR(getAssertionBuffer)
            })
            .then((ctap2Response) => {
                let cborMakeCredResponse = ctap2Response.cborResponseStruct;
                let authDataStruct = parseAuthData(cborMakeCredResponse[GetAssertionRespKeys.authData]);

                assert.isTrue(authDataStruct.flags.uv, 'For CTAP2 request that is done with user verification using pin, UV flag MUST be set to true!');
            })
    })
})
