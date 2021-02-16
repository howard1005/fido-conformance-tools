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

        WebAuthn-Platform-MakeCred-Req-7

        Test platform processing AuthenticatorSelectionCriteria and AttestationConveyancePreference

    `, function() {

    beforeEach(function() {
        this.timeout(10000)
        return TimeoutPromise(2000)
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid MakeCredential request with AttestationConveyancePreference set to "none", check that API succeeds. Parse attestationObject and check that:
            (a) "fmt" is set to "none"
            (b) "attStmt" is set to empty MAP
            (c) Parse "authData" and check that AAGUID is set to 0x00000000000000000000000000000000

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
        publicKey.attestation = 'none';
        return navigator.credentials.create({ publicKey })
            .then((response) => window.navigator.fido.webauthn.decodeToJSON(response.response.attestationObject))
            .then((response) => {
                assert.isDefined(response.fmt, 'Response is missing "fmt" field!')
                assert.strictEqual(response.fmt, 'none', 'For AttestationConveyancePreference set to "none", Response.fmt must be set to "none"!');

                assert.isDefined(response.attStmt, 'Response is missing "fmt" field!')
                assert.deepEqual(response.attStmt, {}, 'For AttestationConveyancePreference set to "none", Response.attStmt must be set to an empty MAP!');

                assert.isDefined(response.authData, 'Response is missing "authData" field!')
                let authDataStruct = parseAuthData(hex.decode(response.authData));

                assert.strictEqual(authDataStruct.aaguid, '00000000-0000-0000-0000-000000000000', 'For AttestationConveyancePreference set to "none", Response.authData.aaguid must be set to 0x0000000000000000000000000000000!');
            })
    })

    it(`P-2

        Send a valid MakeCredential request with AttestationConveyancePreference set to undefined, check that API succeeds. Parse attestationObject and check that:
            (a) "fmt" is set to "none"
            (b) "attStmt" is set to empty MAP
            (c) Parse "authData" and check that AAGUID is set to 0x00000000000000000000000000000000

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
        publicKey.attestation = undefined;
        return navigator.credentials.create({ publicKey })
            .then((response) => window.navigator.fido.webauthn.decodeToJSON(response.response.attestationObject))
            .then((response) => {
                assert.isDefined(response.fmt, 'Response is missing "fmt" field!')
                assert.strictEqual(response.fmt, 'none', 'For AttestationConveyancePreference set to "none", Response.fmt must be set to "none"!');

                assert.isDefined(response.attStmt, 'Response is missing "fmt" field!')
                assert.deepEqual(response.attStmt, {}, 'For AttestationConveyancePreference set to "none", Response.attStmt must be set to an empty MAP!');

                assert.isDefined(response.authData, 'Response is missing "authData" field!')
                let authDataStruct = parseAuthData(hex.decode(response.authData));

                assert.strictEqual(authDataStruct.aaguid, '00000000-0000-0000-0000-000000000000', 'For AttestationConveyancePreference set to "none", Response.authData.aaguid must be set to 0x0000000000000000000000000000000!');
            })
    })

    it(`P-3

        Send a valid MakeCredential request with AttestationConveyancePreference set to "direct", and check that API succeeds

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.attestation = 'direct';
        return navigator.credentials.create({ publicKey })
    })
})
