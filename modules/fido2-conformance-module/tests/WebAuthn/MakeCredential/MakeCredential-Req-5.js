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

        WebAuthn-Platform-MakeCred-Req-5

        Test platform processing PublicKeyCredentialParameters sequence

    `, function() {

    beforeEach(function() {
        this.timeout(10000)
        return TimeoutPromise(2000)
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    // it(`P-1

    //     Send a valid MakeCredential request with "pubKeyCredParams" containing PublicKeyCredentialParameters with "type" set to unknown to authenticator type, and check that API succeeds

    // `, () => {
    //     let publicKey = generateGoodWebAuthnMakeCredential();
    //         publicKey.pubKeyCredParams.push({'type': generateRandomWord(), 'alg': -65535 })

    //     return navigator.credentials.create({ publicKey })
    // })
/* ----- NEGATIVE TESTS ----- */

    describe(`F-1

        Send two MakeCredential requests, that have "pubKeyCredParams" that are containing PublicKeyCredentialParameters with "type" field set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialParameters.type = null`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.pubKeyCredParams.push({'alg': -259, 'type': null})
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })

        it(`PublicKeyCredentialParameters.type = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.pubKeyCredParams.push({'alg': -259})
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    describe(`F-2

        Send two MakeCredential requests, that have "pubKeyCredParams" that are containing PublicKeyCredentialParameters with "alg" field set to null and undefined and check that API fails on both

    `, () => {
        it(`PublicKeyCredentialParameters.alg = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.pubKeyCredParams.push({'type': 'public-key'})
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })

        it(`PublicKeyCredentialParameters.alg = null`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.pubKeyCredParams.push({'alg': null, 'type': 'public-key'})
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    it(`F-3

        Send MakeCredential request with "pubKeyCredParams" that only contains PublicKeyCredentialParameters with "alg" set to algorithm that is not supported by the platform, and check that API fails

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.pubKeyCredParams[0].alg = -0x42;
        return expectPromiseToFail(navigator.credentials.create({ publicKey }))
    })
})
