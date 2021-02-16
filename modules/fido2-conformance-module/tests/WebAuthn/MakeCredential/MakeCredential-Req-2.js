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

        WebAuthn-Platform-MakeCred-Req-2

        Test Platform processing MakeCredential request

    `, function() {

    beforeEach(function() {
        this.timeout(10000)
        return TimeoutPromise(2000)
    })
    this.timeout(120000);

/* ----- NEGATIVE TESTS ----- */
    describe(`F-1

        Send two MakeCredential requests with PublicKeyCredentialCreationOptions.rp set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialCreationOptions.rp = null`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.rp  = null;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })

        it(`PublicKeyCredentialCreationOptions.rp = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.rp  = undefined;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    describe(`F-2

        Send two MakeCredential requests with PublicKeyCredentialCreationOptions.user set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialCreationOptions.user = null`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.user = null;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })

        it(`PublicKeyCredentialCreationOptions.user = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.user = undefined;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    describe(`F-3

        Send two MakeCredential requests with PublicKeyCredentialCreationOptions.challenge set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialCreationOptions.challenge = null`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.challenge = null;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })

        it(`PublicKeyCredentialCreationOptions.challenge = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.challenge = undefined;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    describe(`F-4

        Send two MakeCredential requests with PublicKeyCredentialCreationOptions.pubKeyCredParams set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialCreationOptions.pubKeyCredParams = null`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.pubKeyCredParams = null;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })

        it(`PublicKeyCredentialCreationOptions.pubKeyCredParams = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.pubKeyCredParams = undefined;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })
})
