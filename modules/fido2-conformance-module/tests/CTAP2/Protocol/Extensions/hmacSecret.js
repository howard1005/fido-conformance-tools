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

        HMAC-Secret

        Test HMAC-Secret support

    `, function() {

    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return sendValidCTAP_CBOR(generateGetInfoRequest())
            .then((ctap2Response) => {
                let cborResponse = ctap2Response.cborResponse;

                let supportedExtensions = cborResponse[GetInfoRespKeys.extensions];
                if(!supportedExtensions || !arrayContainsItem(supportedExtensions, 'hmac-secret')) {
                    this.skip()
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

        Send a valid CTAP2 authenticatorClientPin(0x01) message with getKeyAgreement(0x02) subCommand, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) check that authenticatorClientPin_Response contains "keyAgreement" field, and its of type MAP
            (b) in COSE "keyAgreement" field:
                (1) check that public key is EC2(kty(1) is set to 2) 
                (2) check that key crv(-1) curve field that is set to P256(1)
                (3) check that key alg(3) is set to ECDH-ES+HKDF-256(-25)
                (4) check that key contains x(-2) is of type BYTE STRING, and is 32bytes long 
                (5) check that key contains y(-3) is of type BYTE STRING, and is 32bytes long 
                (6) check that key does NOT contains ANY other coefficients

    `, () => {
        let commandBuffer = generateClientPin_GetKeyAgreement();
        return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            .then((response) => {
                let cborResponse = response.cborResponse;
                let cborResponseStruct = response.cborResponseStruct;

                assert.isDefined(cborResponse[ClientPinRespKeys.keyAgreement], 'authenticatorClientPin_Response missing "keyAgreement" field!');
                assert.isObject(cborResponse[ClientPinRespKeys.keyAgreement], 'authenticatorClientPin_Response.keyAgreement MUST be of type MAP');

                let keyStruct = cborResponse[ClientPinRespKeys.keyAgreement];
                let keyCBORStruct = cborResponseStruct[ClientPinRespKeys.keyAgreement];

                assert.isDefined(keyStruct[COSE_KEYS.kty], 'keyAgreement is missing "kty" key!');
                assert.isNumber(keyStruct[COSE_KEYS.kty], 'keyAgreement.kty MUST be of type NUMBER!');
                assert.strictEqual(keyStruct[COSE_KEYS.kty], COSE_KTY.EC2, 'keyAgreement.kty MUST be set to EC2(2)');

                assert.isDefined(keyStruct[COSE_KEYS.alg], 'keyAgreement is missing "alg" key!');
                assert.isNumber(keyStruct[COSE_KEYS.alg], 'keyAgreement.alg MUST be of type NUMBER!');
                // assert.strictEqual(keyStruct[COSE_KEYS.alg], COSE_ALG_EC2['ECDH-ES+HKDF-256'], 'keyAgreement.alg MUST be set to ECDH-ES+HKDF-256(-25)');

                if(keyStruct[COSE_KEYS.crv]) {
                    assert.isNumber(keyStruct[COSE_KEYS.crv], 'keyAgreement.crv MUST be of type NUMBER!');
                    assert.strictEqual(keyStruct[COSE_KEYS.crv], COSE_CRV['P-256'], 'keyAgreement.crv MUST be set to P-256(1)');
                }

                assert.isDefined(keyStruct[COSE_KEYS.x], 'Public key is missing x coefficient!');
                assert.strictEqual(type(keyCBORStruct[COSE_KEYS.x]), 'Uint8Array', 'x coefficient MUST be of type BYTE STRING!');
                assert.strictEqual(keyCBORStruct[COSE_KEYS.x].byteLength, 32, 'x coefficient MUST be exactly 32 bytes long!');

                assert.isDefined(keyStruct[COSE_KEYS.y], 'Public key is missing y coefficient!');
                assert.strictEqual(type(keyCBORStruct[COSE_KEYS.y]), 'Uint8Array', 'y coefficient MUST be of type BYTE STRING!');
                assert.strictEqual(keyCBORStruct[COSE_KEYS.y].byteLength, 32, 'y coefficient MUST be exactly 32 bytes long!');

                let allowedCOSEKeys = [COSE_KEYS.kty, COSE_KEYS.alg, COSE_KEYS.crv, COSE_KEYS.x, COSE_KEYS.y].map(String)
                assert.deepEqual(Object.keys(keyStruct), allowedCOSEKeys, 'Public key contains unexpected coefficients! Only kty, alg, crv, x and y are allowed!');
            })
    })

    let hmacCredId = undefined
    let rpId       = undefined

    it(`P-2

        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containg a valid "hmac-secret" set to true, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, with extensions payload containing 'hmac-secret' field set to true

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let extensions = {
            'hmac-secret': true
        }

        rpId = makeCredStruct.rp.id;

        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, extensions)

        return sendValidCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
                let authDataBuffer = ctap2Response.cborResponseStruct[MakeCredentialsRespKeys.authData];
                let authDataStruct = parseAuthData(authDataBuffer);

                assert.isDefined(authDataStruct.extensionsData, 'Authenticator did not return any extensions data, despite claiming it\'s support of the "hmac-secret" extension!')
                let extensionsStruct = vanillaCBOR.decode(authDataStruct.extensionsData)[0];
                assert.isDefined(extensionsStruct['hmac-secret'], 'Extensions data does not contain any response for "hmac-secret" extension, despite claiming of it\'s support!')

                assert.isBoolean(extensionsStruct['hmac-secret'], 'Extensions response for "hmac-secret" for MakeCredentials command must be of type BOOLEAN!');
                assert.isTrue(extensionsStruct['hmac-secret'], 'Extensions response for "hmac-secret" for MakeCredentials command must be TRUE!');

                hmacCredId = authDataStruct.credId;
            })
    })

    it(`P-3

        Send a valid CTAP2 getAssertion(0x02) message, "extensions" containg a valid "hmac-secret" extension request, with one salt, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) Check that response contains extensions encrypted "hmac-secret" extension response. Decrypt it and save it as salt1hmac
            (b) Send another GetAssertion with salt1 and check that response still equal to salt1hmac

    `, () => {
        if(!hmacCredId)
            throw new Error('This test is failed because previous test has failed as well!');

        let credId       = hmacCredId
        hmacCredId       = undefined;

        let salt1        = generateRandomBuffer(32);
        let salt1Hmac    = undefined;
        let sharedSecret = undefined;

        return establishKeyAgreement()                
            .then((ka) => {
                sharedSecret = ka.sharedSecret;

                let getAssertionStruct = generateGoodCTAP2GetAssertion();
                let allowList      = [
                    { 'type': 'public-key', 'id': credId }
                ]

                let saltEnc       = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(ka.sharedSecret, salt1);
                let newPinEncHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(ka.sharedSecret, saltEnc);
                let saltAuth      = newPinEncHMAC.slice(0, 16);

                let extensions = {
                    'hmac-secret': {
                        0x01: ka.keyAgreement,
                        0x02: saltEnc,
                        0x03: saltAuth
                    }
                }

                let commandBuffer  = generateGetAssertionReqCBOR(rpId, getAssertionStruct.clientDataHash, allowList, extensions)

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
                let authDataBuffer = ctap2Response.cborResponseStruct[GetAssertionRespKeys.authData];
                let authDataStruct = parseAuthData(authDataBuffer);

                assert.isDefined(authDataStruct.extensionsData, 'Authenticator did not return any extensions data, despite claiming it\'s support of the "hmac-secret" extension!')
                let extensionsStruct = vanillaCBOR.decode(authDataStruct.extensionsData)[0];
                assert.isDefined(extensionsStruct['hmac-secret'], 'Extensions data does not contain any response for "hmac-secret" extension, despite claiming of it\'s support!')
                salt1Hmac = window.navigator.fido.fido2.crypto.decryptAES256CBCIV0(sharedSecret, extensionsStruct['hmac-secret'])

                /* ----- GET ASSERTION ----- */

                return establishKeyAgreement()                
            })
            .then((ka) => {
                sharedSecret = ka.sharedSecret;

                let getAssertionStruct = generateGoodCTAP2GetAssertion();
                let allowList      = [
                    { 'type': 'public-key', 'id': credId }
                ]

                let saltEnc       = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(ka.sharedSecret, salt1);
                let newPinEncHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(ka.sharedSecret, saltEnc);
                let saltAuth      = newPinEncHMAC.slice(0, 16);

                let extensions = {
                    'hmac-secret': {
                        0x01: ka.keyAgreement,
                        0x02: saltEnc,
                        0x03: saltAuth
                    }
                }

                let commandBuffer  = generateGetAssertionReqCBOR(rpId, getAssertionStruct.clientDataHash, allowList, extensions)

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
                let authDataBuffer = ctap2Response.cborResponseStruct[GetAssertionRespKeys.authData];
                let authDataStruct = parseAuthData(authDataBuffer);

                assert.isDefined(authDataStruct.extensionsData, 'Authenticator did not return any extensions data, despite claiming it\'s support of the "hmac-secret" extension!')
                let extensionsStruct = vanillaCBOR.decode(authDataStruct.extensionsData)[0];
                assert.isDefined(extensionsStruct['hmac-secret'], 'Extensions data does not contain any response for "hmac-secret" extension, despite claiming of it\'s support!')
                let salt1Hmac2 = window.navigator.fido.fido2.crypto.decryptAES256CBCIV0(sharedSecret, extensionsStruct['hmac-secret'])

                assert.strictEqual(hex.encode(salt1Hmac), hex.encode(salt1Hmac2), 'Authenticator did not return expected HMAC!');

                hmacCredId = credId;
            })
    })

    it(`P-4

        For two salts

        Send a valid CTAP2 getAssertion(0x02) message, "extensions" containg a valid "hmac-secret" extension request with two salts, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code, and:
            (a) Check that response contains extensions encrypted "hmac-secret" extension response that is 64bytes long. Decrypt it and save it as salt1hmac and salt2hmac
            (b) Send another GetAssertion with randomSalt and salt2 and check that response still contains salt2Hmac
            (c) Send another GetAssertion with salt1 and randomSalt and check that response still contains salt1Hmac
            (d) Send another GetAssertion with salt1 and salt2 and check that response still contains salt1Hmac and salt2Hmac
            (e) Send another GetAssertion with salt2 and salt1 and check that response still contains salt2Hmac and salt1Hmac

    `, () => {
        if(!hmacCredId)
            throw new Error('This test is failed because previous test has failed as well!');

        let credId       = hmacCredId
        hmacCredId       = undefined;

        var salt1        = generateRandomBuffer(32);
        var salt2        = generateRandomBuffer(32);
        var salt1Hmac    = undefined;
        var salt2Hmac    = undefined;

        return sendHmacSecretGetAssertion(rpId, credId, salt1, salt2)
            .then((response) => {
                salt1Hmac = response.salt1Hmac
                salt2Hmac = response.salt2Hmac

                return sendHmacSecretGetAssertion(rpId, credId, generateRandomBuffer(32), salt2)
            })
            .then((response) => {
                assert.strictEqual(hex.encode(response.salt2Hmac), hex.encode(salt2Hmac), 'Authenticator returned unexpected salt2Hmac!')

                return sendHmacSecretGetAssertion(rpId, credId, salt1, generateRandomBuffer(32))
            })
            .then((response) => {
                assert.strictEqual(hex.encode(response.salt1Hmac), hex.encode(salt1Hmac), 'Authenticator returned unexpected salt1Hmac!')

                return sendHmacSecretGetAssertion(rpId, credId, salt1, salt2)
            })
            .then((response) => {
                assert.strictEqual(hex.encode(response.salt1Hmac), hex.encode(salt1Hmac), 'Authenticator returned unexpected salt1Hmac!')
                assert.strictEqual(hex.encode(response.salt2Hmac), hex.encode(salt2Hmac), 'Authenticator returned unexpected salt2Hmac!')

                return sendHmacSecretGetAssertion(rpId, credId, salt2, salt1)
            })
            .then((response) => {
                assert.strictEqual(hex.encode(response.salt2Hmac), hex.encode(salt1Hmac), 'Authenticator returned unexpected salt1Hmac!')
                assert.strictEqual(hex.encode(response.salt1Hmac), hex.encode(salt2Hmac), 'Authenticator returned unexpected salt2Hmac!')

                hmacCredId = credId;
            })
    })

    /* ----- NEGATIVE TESTS ----- */

    it(`F-1

        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "extensions" containg "hmac-secret" set to a random type, wait for the response, and check that Authenticator returns an error

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let extensions = {
            'hmac-secret': generateRandomTypeExcluding('boolean')
        }

        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, extensions)

        return expectPromiseToFail(sendValidCTAP_CBOR(commandBuffer))
    })

    it(`F-2

        Send a CTAP2 getAssertion(0x02) message, with "extensions" containg a "hmac-secret" extension request with one salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error

    `, () => {
        if(!hmacCredId)
            throw new Error('This test is failed because previous test(s) has failed as well!');

        let credId       = hmacCredId
        hmacCredId       = undefined;

        return expectPromiseToFail(sendHmacSecretGetAssertion(rpId, credId, generateRandomBuffer(generateSecureRandomInt(1, 31))))
            .then(() => {
                hmacCredId = credId;
            })
    })

    it(`F-3

        Send a CTAP2 getAssertion(0x02) message, with "extensions" containg a "hmac-secret" extension request with two salts, with second salt that is shorter than 32 bytes, wait for the response, and check that authenticator returns an error

    `, () => {
        if(!hmacCredId)
            throw new Error('This test is failed because previous test(s) has failed as well!');

        let credId       = hmacCredId
        hmacCredId       = undefined;

        return expectPromiseToFail(sendHmacSecretGetAssertion(rpId, credId, generateRandomBuffer(32), generateRandomBuffer(generateSecureRandomInt(1, 31))))
            .then(() => {
                hmacCredId = credId;
            })
    })
})


































