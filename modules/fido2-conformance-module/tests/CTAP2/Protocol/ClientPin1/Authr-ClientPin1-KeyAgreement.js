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

        Authr-ClientPin1-GetKeyAgreement

        Test authenticatorClientPin(0x06), of version 0x01 support of getKeyAgreement(0x02) command

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
})

