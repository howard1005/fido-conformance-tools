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

        Authr-MakeCred-Resp-1

        Test registration response

    `, function() {

    let makeCredResponses  = undefined
    let metadata           = window.config.test.metadataStatement;
    let rpId               = generateRandomDomain();
    let rpIdHash           = undefined;
    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')


        rpIdHash = window.navigator.fido.fido2.crypto.hash('sha256', rpId);
        return getMakeCredentialResponseForAllAlgorithms(rpId)
        .then((responses) => {
            makeCredResponses = responses;
        })
    })

    after(function() {
        this.timeout(30000);
        return sendReset()
    })

    this.timeout(30000);
    // this.retries(3);
    
    let MakeCredRespKeys = {
        'fmt'      : 0x01,
        'authData' : 0x02,
        'attStmt'  : 0x03
    }

/* ----- POSITIVE TESTS ----- */

    it(`P-01

        Send a valid CTAP2 authenticatorMakeCreditential(0x01) message, wait for the response, and check that: 
            (a) Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code 
            (b) Response structure can be successfully parsed 
            (c) Response.fmt is of type String 
            (d) Response.fmt is set to either "packed", "tpm", "android-key" or "android-safetynet"

    `, () => {
        for(let response of makeCredResponses) {
            let cborResponse       = response.cborResponse;
            let cborResponseStruct = response.cborResponseStruct;

            let typesOfAttestation = ['packed', 'tpm', 'android-key', 'android-safetynet'];
            assert.isString(cborResponse[MakeCredRespKeys.fmt], 'AuthenticatorAttestationResponse.fmt MUST be of type STRING!');
            assert.include(typesOfAttestation, cborResponse[MakeCredRespKeys.fmt], 'AuthenticatorAttestationResponse.fmt is set to an Unknown attestation format. Must be either of ' + typesOfAttestation)
        }
        
    })

    it(`P-02

        Using previously received response, check that: 
            (a) response.authData is of type BYTE ARRAY 
            (b) check that authData is at least (32 + 1 + 4 + 16 + 2 + 16 + 77) bytes long. 
            (c) parse response.authData 
            (d) check that AAGUID matching the one in metadata statement 
            (e) check that authData.rpIdHash matches the sent rpIdHash 
            (f) check that UP(bit 0) flag in flags is set 
            (g) check that AT(bit 6) flag in flags is set, and attestation credential data is presented 
            (h) check that ED(bit 7) flag in flags is not set, and check that there is not Extension Data present
            (i) check that authData.pubKey is correctly encoded:
            (j) if public key is an RSA(kty(1) is set to 3) public key, check that: 
                (1) alg(2) is set to algorithm that matches corresponding one in metadata statement
                (2) contains n(-1) that is of type BYTE STRING 
                (3) contains e(-2) that is of type BYTE STRING 
                (4) does NOT contains ANY other coefficients
            (k) if public key is an EC2(kty(1) is set to 2) public key, check that: 
                (1) alg(2) is set to algorithm that matches corresponding one in metadata statement
                (2) crv(-1) field that is set to EC identifier from "COSE Elliptic Curves" registry
                (3) contains x(-2) is of type BYTE STRING, and is 32bytes long 
                (4) contains y(-3) is of type BYTE STRING, and is 32bytes long 
                (5) does NOT contains ANY other coefficients
            (k) if public key is an OKP(kty(1) is set to 1) public key, check that: 
                (1) alg(2) is set to algorithm that matches corresponding one in metadata statement
                (2) crv(-1) field that is set to EdDSA identifier from "COSE Elliptic Curves" registry
                (3) contains x(-2) is of type BYTE STRING, and is 32bytes long 
                (5) does NOT contains ANY other coefficients

    `, () => {
        for(let response of makeCredResponses) {
            let cborResponse       = response.cborResponse;
            let cborResponseStruct = response.cborResponseStruct;

            assert.strictEqual(type(cborResponseStruct[MakeCredRespKeys.authData]), 'Uint8Array', 'AuthenticatorAttestationResponse.authData MUST be of type BYTE ARRAY!');
            assert.isAtLeast(cborResponseStruct[MakeCredRespKeys.authData].byteLength, 32 + 1 + 4 + 16 + 2 + 16 + 77, 'Incorectly formated data. MUST be at least 146bytes!');
            let authDataStruct = parseAuthData(cborResponseStruct[MakeCredRespKeys.authData]);

            assert.strictEqual(authDataStruct.aaiguid, metadata.aaiguid, 'authData.AAGUID in response does not match AAGUID in metadata.')
            assert.strictEqual(hex.encode(authDataStruct.rpIdHash), hex.encode(rpIdHash), 'authData.rpIdHash does not match rpIdHash!')

            assert.isTrue(authDataStruct.flags.up, 'UP bit is NOT set!');
            assert.isTrue(authDataStruct.flags.at, 'AT bit is NOT set!');

            let keyStruct     = tryDecodeCBORtoJSON(authDataStruct.COSEPublicKey)[0];
            let keyCBORStruct = tryDecodeCBORtoCBORSTRUCT(authDataStruct.COSEPublicKey)[0];
            
            assert.isDefined(COSE_KTY[keyStruct[COSE_KEYS.kty]], 'Public key contains an unknown KTY!');
            assert.isDefined(getFIDOAlgorithm(keyStruct), 'The given COSE key in not in FIDO Registry!');

            let fidoAlgIdentifier = getFIDOAlgorithm(keyStruct)
            assert.isDefined(fidoAlgIdentifier, 'Given public key type is in FIDO Registry!');
            assert.strictEqual(metadata.authenticationAlgorithm, ALG_DIR_TO_INT[fidoAlgIdentifier], 'Response signature algorithm does not match metadata statement authenticationAlgorithm!');

            if(keyStruct[COSE_KEYS.kty] === COSE_KTY.RSA) {
                assert.isDefined(keyStruct[COSE_KEYS.n], 'Public key is missing n coefficient!');
                assert.strictEqual(type(keyCBORStruct[COSE_KEYS.n]), 'Uint8Array', 'n coefficient MUST be of type BYTE STRING!');
                assert.notStrictEqual(keyCBORStruct[COSE_KEYS.n].byteLength, 0, 'n coefficient MUST not be empty!')

                assert.isDefined(keyStruct[COSE_KEYS.e], 'Public key is missing e coefficient!');
                assert.strictEqual(type(keyCBORStruct[COSE_KEYS.e]), 'Uint8Array', 'e coefficient MUST be of type BYTE STRING!');
                assert.notStrictEqual(keyCBORStruct[COSE_KEYS.e].byteLength, 0, 'e coefficient MUST not be empty!')

                let allowedCOSEKeys = [COSE_KEYS.kty, COSE_KEYS.alg, COSE_KEYS.n, COSE_KEYS.e].map(String)
                assert.deepEqual(Object.keys(keyStruct), allowedCOSEKeys, 'Public key contains unexpected coefficients! Only kty, alg, n and e are allowed!');
            } else if(keyStruct[COSE_KEYS.kty] === COSE_KTY.EC2) {
                assert.isDefined(keyStruct[COSE_KEYS.x], 'Public key is missing x coefficient!');
                assert.strictEqual(type(keyCBORStruct[COSE_KEYS.x]), 'Uint8Array', 'x coefficient MUST be of type BYTE STRING!');
                assert.strictEqual(keyCBORStruct[COSE_KEYS.x].byteLength, 32, 'x coefficient MUST be exactly 32 bytes long!');

                assert.isDefined(keyStruct[COSE_KEYS.y], 'Public key is missing y coefficient!');
                assert.strictEqual(type(keyCBORStruct[COSE_KEYS.y]), 'Uint8Array', 'y coefficient MUST be of type BYTE STRING!');
                assert.strictEqual(keyCBORStruct[COSE_KEYS.y].byteLength, 32, 'y coefficient MUST be exactly 32 bytes long!');

                let allowedCOSEKeys = [COSE_KEYS.kty, COSE_KEYS.alg, COSE_KEYS.crv, COSE_KEYS.x, COSE_KEYS.y].map(String)
                assert.deepEqual(Object.keys(keyStruct), allowedCOSEKeys, 'Public key contains unexpected coefficients! Only kty, alg, crv, x and y are allowed!');
             } else if(keyStruct[COSE_KEYS.kty] === COSE_KTY.OKP) {
                assert.isDefined(keyStruct[COSE_KEYS.x], 'Public key is missing x coefficient!');
                assert.strictEqual(type(keyCBORStruct[COSE_KEYS.x]), 'Uint8Array', 'x coefficient MUST be of type BYTE STRING!');
                assert.strictEqual(keyCBORStruct[COSE_KEYS.x].byteLength, 32, 'x coefficient MUST be exactly 32 bytes long!');

                let allowedCOSEKeys = [COSE_KEYS.kty, COSE_KEYS.alg, COSE_KEYS.crv, COSE_KEYS.x].map(String)
                assert.deepEqual(Object.keys(keyStruct), allowedCOSEKeys, 'Public key contains unexpected coefficients! Only kty, alg, crv, x and y are allowed!');
             }
        }
    })
})
