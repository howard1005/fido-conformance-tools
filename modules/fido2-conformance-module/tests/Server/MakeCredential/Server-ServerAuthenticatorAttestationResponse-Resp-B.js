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

        Server-ServerAuthenticatorAttestationResponse-Resp-B

        Test server processing "android-safetynet" attestation

    `, function() {

    let serverURL = window.config.test.serverURL;
    let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSA PKCS 1.5 SHA256 FIDO2 Conformance Testing CTAP2 Authenticator with SafetyNet attestation'], 'android-safetynet', serverURL);

    this.timeout(30000);
    this.retries(3);

/* ----- POSITIVE TESTS ----- */

    it(`P-1

        Send a valid ServerAuthenticatorAttestationResponse with "android-safetynet" attestation, and check that server succeeds

    `, () => {
        
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

  
/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "ver" field is empty, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'safetyNetEmptyVer': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-2

        Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "response" field is empty, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'safetyNetEmptyResponse': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-3

        Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "nonce" does not contain a valid attToBeSigned, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'safetyNetInvalidAttToBeSigned': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-4

        Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "x5c" is empty, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'safetyNetEmptyX5C': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-5

        Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "ctsProfileMatch" is false, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'safetyNetFalseCtsProfileMatch': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-6

        Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "timestampMs" is set to future, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'safetyNetTimestampMsIsInFuture': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })


    it(`F-7

        Send ServerAuthenticatorAttestationResponse with "android-safetynet" attestation "timestampMs" is older than 1 minute, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'safetyNetTimestampMsIsOutdated': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })
})