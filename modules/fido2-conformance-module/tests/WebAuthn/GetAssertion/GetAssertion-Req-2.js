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

        WebAuthn-Platform-GetAssertion-Req-2

        Test Platform processing CredentialRequestOptions

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

/* ----- NEGATIVE TESTS ----- */
    describe(`F-1

        Send two GetAssertion requests with CredentialRequestOptions.challenge set to null and undefined and check that API fails on both

    `, () => {
        it(`CredentialRequestOptions.challenge = null`, () => {
            let publicKey = generateGoodWebAuthnGetAssertion(credId);
            publicKey.challenge = null;
            return expectPromiseToFail(navigator.credentials.get({ publicKey }))
        })

        it(`CredentialRequestOptions.challenge = undefined`, () => {
            let publicKey = generateGoodWebAuthnGetAssertion(credId);
            publicKey.challenge = undefined;
            return expectPromiseToFail(navigator.credentials.get({ publicKey }))
        })
    })

    it(`F-2

        Send GetAssertion request with CredentialRequestOptions.rpId set to rpId that is not within the same security context, and check that API fails

    `, () => {
        let publicKey = generateGoodWebAuthnGetAssertion(credId);
        publicKey.rpId = `certainlynotattackersdomain.${generateRandomDomain()}`;
        return expectPromiseToFail(navigator.credentials.get({ publicKey }))
    })
})