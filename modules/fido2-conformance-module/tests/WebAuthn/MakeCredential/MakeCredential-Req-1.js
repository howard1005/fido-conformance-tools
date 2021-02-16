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

        WebAuthn-Platform-MakeCred-Req-1

        Test Platform processing MakeCredential request

    `, function() {

    beforeEach(function() {
        this.timeout(10000)
        return TimeoutPromise(2000)
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid MakeCredential request, and check that API succeeds

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();

        return navigator.credentials.create({ publicKey })
    })

/* ----- NEGATIVE TESTS ----- */
    describe(`F-1

        Send two MakeCredential requests with CredentialCreationOptions set to null and undefined and check that API fails on both

    `, () => {
        it(`CredentialCreationOptions = null`, () => {
            return expectPromiseToFail(navigator.credentials.create(null))
        })

        it(`CredentialCreationOptions = undefined`, () => {
            return expectPromiseToFail(navigator.credentials.create(undefined))
        })
    })

    describe(`F-2

        Send two MakeCredential requests with CredentialCreationOptions.pubKey set to null and undefined and check that API fails on both

    `, () => {
        it(`CredentialCreationOptions.pubKey = null`, () => {
            let publicKey = null;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })

        it(`CredentialCreationOptions.pubKey = undefined`, () => {
            let publicKey = undefined;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })
})