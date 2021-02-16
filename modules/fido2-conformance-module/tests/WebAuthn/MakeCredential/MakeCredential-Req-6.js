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

        WebAuthn-Platform-MakeCred-Req-6

        Test platform processing "excludeCredentials" PublicKeyCredentialDescriptor sequence

    `, function() {

    beforeEach(function() {
        this.timeout(10000)
        return TimeoutPromise(2000)
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid MakeCredential request with "excludeCredentials" set to an empty sequence, and check that API succeeds

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.excludeCredentials = [];
        return navigator.credentials.create({ publicKey })
    })

    // it(`P-2

    //     Send a valid MakeCredential request with "excludeCredentials" containing PublicKeyCredentialDescriptor with "type" set to uknown to authenticator type, and check that API succeeds

    // `, () => {
    //     let publicKey = generateGoodWebAuthnMakeCredential();
    //         publicKey.excludeCredentials = [{'type': generateRandomWord(), 'id': generateRandomBuffer(32)}];
    //     return navigator.credentials.create({ publicKey })
    // })

/* ----- NEGATIVE TESTS ----- */

    describe(`F-1

      Send two MakeCredential requests, that have "excludeCredentials" that are containing PublicKeyCredentialDescriptor with "type" field set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialDescriptor.type = null`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.excludeCredentials = [];
            publicKey.excludeCredentials.push({'id': generateRandomBuffer(32), 'type': null})
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })

        it(`PublicKeyCredentialDescriptor.type = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.excludeCredentials = [];
            publicKey.excludeCredentials.push({'id': generateRandomBuffer(32)})
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    describe(`F-2

        Send two MakeCredential requests, that have "excludeCredentials" that are containing PublicKeyCredentialDescriptor with "id" field set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialDescriptor.id = null`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.excludeCredentials = [];
            publicKey.excludeCredentials.push({'id': null, 'type': 'public-key'})
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })

        it(`PublicKeyCredentialDescriptor.id = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.excludeCredentials = [];
            publicKey.excludeCredentials.push({'type': 'public-key'})
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    it(`F-3

        Send MakeCredential request with "excludeCredentials" contains PublicKeyCredentialDescriptor for the previously registered credential, and check that API fails

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
        return navigator.credentials.create({ publicKey })
            .then((response) => Promise.all([
                window.navigator.fido.webauthn.decodeToJSON(response.response.attestationObject),
                 window.navigator.fido.webauthn.decodeToObjectStruct(response.response.attestationObject)
            ]))
            .then((response) => {
                let attestationObject       = response[0];
                let attestationObjectStruct = response[1];

                let authData = parseAuthData(attestationObjectStruct.authData);

                let publicKey = generateGoodWebAuthnMakeCredential();
                publicKey.excludeCredentials = [{'id': authData.credId, 'type': 'public-key'}];
                return expectPromiseToFail(navigator.credentials.create({ publicKey }))
            })
    })
})
