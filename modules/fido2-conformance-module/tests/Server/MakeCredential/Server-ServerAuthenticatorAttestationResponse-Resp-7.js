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

        Server-ServerAuthenticatorAttestationResponse-Resp-7

        Test server processing "none" attestation

    `, function() {

    let serverURL = window.config.test.serverURL;

    this.timeout(30000);
    this.retries(3);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid ServerAuthenticatorAttestationResponse with SELF(SURROGATE) "packed" attestation, and check that server succeeds

    `, () => {
        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements["Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator"], 'none', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'none'})
            .then((response) => {

                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-2

        Send a valid ServerAuthenticatorAttestationResponse with SELF(SURROGATE) "packed" attestation, and check that server succeeds

    `, () => {
        let webauthnClient = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements["Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator with Self(surrogate) attestation"], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'none'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        For server that expects attestation "none", send attestation FULL packed, with fmt set "none" and check that server returns an error

    `, () => {
        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements["Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator"], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'fmtSetNone': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })
})