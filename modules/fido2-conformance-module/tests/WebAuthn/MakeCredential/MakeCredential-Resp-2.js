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

        WebAuthn-Platform-MakeCred-Resp-2

        Test attestationObject

    `, function() {

    let attestationObject = undefined;
    let attestationObjectStruct = undefined;
    let metadata = undefined;
    before(function() {
        this.timeout(120000);

        let publicKey = generateGoodWebAuthnMakeCredential();
        publicKey.attestation = 'direct';
        metadata = getMetadataStatement();

        return navigator.credentials.create({ publicKey })
            .then((response) => Promise.all([window.navigator.fido.webauthn.decodeToJSON(response.response.attestationObject),
                                             window.navigator.fido.webauthn.decodeToObjectStruct(response.response.attestationObject)]))
            .then((response) => {
                attestationObject = response[0];
                attestationObjectStruct = response[1];
            })
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid MakeCredential request, wait for the response, and check that: 
            (a) Response was successfull
            (a) Response.response.attestationObject structure can be successfully parsed 
            (b) Response.fmt is of type String 
            (c) Response.fmt is set to either "tpm" or "android-safetynet"

    `, () => {
        assert.isDefined(attestationObject.fmt, 'Response is missing "fmt" field!')
        assert.include(['tpm', 'android-safetynet', 'packed'], attestationObject.fmt, 'Response.fmt MUST be set to either of "tpm", "packed" or "android-safetynet"!');
    })

    it(`P-2

        Using previously received response, check that: 
            (a) attestationObject.authData is of type BYTE ARRAY 
            (b) check that authData is at least (32 + 1 + 4 + 16 + 2 + 16 + 77) bytes long. 
            (c) parse attestationObject.authData 
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
                (4) does NOT contains ANY other coefficients

    `, () => {
        assert.strictEqual(type(attestationObjectStruct.authData), 'Uint8Array', 'attestationObject.authData MUST be of type BYTE ARRAY!')
        assert.isAtLeast(attestationObjectStruct.authData.byteLength, 32 + 1 + 4 + 16 + 2 + 16 + 77, 'attestationObject.authData MUST be at least 32 + 1 + 4 + 16 + 2 + 16 + 77 bytes long!');

        let authData = parseAuthData(attestationObjectStruct.authData);
        assert.strictEqual(authData.aaguid, metadata.aaguid, 'authData AAGUID does not match the AAGUID in metadata statement!');

        assert.isTrue(authData.flags.up, 'For MakeCredential, User Presence MUST be enforced!');
        assert.isTrue(authData.flags.at, 'For MakeCredential, Attestation Data flag must be set!');
        assert.isFalse(authData.flags.ed, 'For MakeCredential, with no Extensions requested, Extensions Data flag MUST not be set!');

        return Promise.all([
                window.navigator.fido.webauthn.decodeToJSON(authData.COSEPublicKey),
                window.navigator.fido.webauthn.decodeToObjectStruct(authData.COSEPublicKey),
                window.navigator.fido.webauthn.hash('SHA-256', stringToArrayBuffer(window.location.hostname))
            ])
            .then((response) => {
                let keyStruct          = response[0];
                let keyCBORStruct      = response[1];
                let rpIdHashCalculated = response[2];

                assert.strictEqual(hex.encode(rpIdHashCalculated), hex.encode(authData.rpIdHash), 'AuthData does not contain expected rpIdHash!');

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
            })
    })
})
