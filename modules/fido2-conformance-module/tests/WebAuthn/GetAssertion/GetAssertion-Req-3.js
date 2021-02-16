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

        WebAuthn-Platform-GetAssertion-Req-3

        Test platform processing "allowCredentials" PublicKeyCredentialDescriptor sequence

    `, function() {


    let credId = undefined;
    before(function() {
        this.timeout(120000);

        let publicKey         = generateGoodWebAuthnMakeCredential();
        publicKey.attestation = 'direct';

        return navigator.credentials.create({ publicKey })
            .then((response) => Promise.all([window.navigator.fido.webauthn.decodeToJSON(response.response.attestationObject),
                                             window.navigator.fido.webauthn.decodeToObjectStruct(response.response.attestationObject)]))
            .then((response) => {
                let attestationObject       = response[0];
                let attestationObjectStruct = response[1];

                let authData = parseAuthData(attestationObjectStruct.authData);

                credId = authData.credId;
            })
    })
    beforeEach(function() {
        this.timeout(10000)
        return TimeoutPromise(2000)
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid GetAssertion request with "allowCredentials" contains PublicKeyCredentialDescriptor for the previously registered credential, and check that API succeeds

    `, () => {
        let publicKey = generateGoodWebAuthnGetAssertion(credId);

        return navigator.credentials.get({ publicKey })
    })

    it(`P-2

        Send a valid GetAssertion request with "allowCredentials" containing PublicKeyCredentialDescriptor with "transports", and check that API succeeds

    `, () => {
        let publicKey = generateGoodWebAuthnGetAssertion(credId);
        publicKey.allowCredentials[0].transports = ['usb', 'nfc', 'ble', 'internal'];
        return navigator.credentials.get({ publicKey })
    })

/* ----- NEGATIVE TESTS ----- */
    describe(`F-1

        Send two GetAssertion requests, that have "allowCredentials" that are containing PublicKeyCredentialDescriptor with "type" field set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialDescriptor.type = null`, () => {
            let publicKey = generateGoodWebAuthnGetAssertion(credId);
            publicKey.allowCredentials = [{'type': null}, publicKey.allowCredentials[0]];
            return expectPromiseToFail(navigator.credentials.get({ publicKey }))
        })

        it(`PublicKeyCredentialDescriptor.type = undefined`, () => {
            let publicKey = generateGoodWebAuthnGetAssertion(credId);
            publicKey.allowCredentials = [{'type': undefined}, publicKey.allowCredentials[0]];
            return expectPromiseToFail(navigator.credentials.get({ publicKey }))
        })
    })

    describe(`F-2

        Send two GetAssertion requests, that have "allowCredentials" that are containing PublicKeyCredentialDescriptor with "id" field set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialDescriptor.id = null`, () => {
            let publicKey = generateGoodWebAuthnGetAssertion(credId);
            publicKey.allowCredentials = [{'type': 'public-key', 'id': null}, publicKey.allowCredentials[0]];
            return expectPromiseToFail(navigator.credentials.get({ publicKey }))
        })

        it(`PublicKeyCredentialDescriptor.id = undefined`, () => {
            let publicKey = generateGoodWebAuthnGetAssertion(credId);
            publicKey.allowCredentials = [{'type': 'public-key', 'id': undefined}, publicKey.allowCredentials[0]];
            return expectPromiseToFail(navigator.credentials.get({ publicKey }))
        })
    })

    it(`F-3

       Send GetAssertion request with "allowCredentials" that are containing PublicKeyCredentialDescriptor with "id" set to an unknown credId, and check that API fails

    `, () => {
        let publicKey = generateGoodWebAuthnGetAssertion(credId);
        publicKey.allowCredentials[0].id = generateRandomBuffer(32);
        return expectPromiseToFail(navigator.credentials.get({ publicKey }))
    })
})