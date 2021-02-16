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

        Server-ServerAuthenticatorAttestationResponse-Resp-1

        Test server processing ServerAuthenticatorAttestationResponse structure

    `, function() {

    let serverURL = undefined;

    this.timeout(30000);
    this.retries(3);

    before(() => {
        if(!confirm('Have you registered you serverURL at https://mds.certinfra.fidoalliance.org/ and added provided MDS endpoints to your server?'))
            throw new Error('Waiting for user to add metadata service endpoints...')

        serverURL = window.config.test.serverURL;
    })

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for a valid MDS metadata, and check that server succeeds

    `, () => {
        let webauthnClient = undefined;
        return getMDSMetadataForTestCase(serverURL, 'good')
            .then((metadata) => {
                webauthnClient = new window.CTAP.WebauthnClient(metadata, 'packed', serverURL);
                let username       = generateRandomString();
                let displayName    = generateRandomName();
                return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            })
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's hash can not be verified, and check that serve returns an error

    `, () => {
        let webauthnClient = undefined;
        return getMDSMetadataForTestCase(serverURL, 'badHashes')
            .then((metadata) => {
                webauthnClient  = new window.CTAP.WebauthnClient(metadata, 'packed', serverURL);
                let username       = generateRandomString();
                let displayName    = generateRandomName();
                return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            })
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-2

        Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's status is set to USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE or USER_KEY_PHYSICAL_COMPROMISE, and check that serve returns an error

    `, () => {
        let webauthnClient = undefined;
        return getMDSMetadataForTestCase(serverURL, 'badReports')
            .then((metadata) => {
                webauthnClient  = new window.CTAP.WebauthnClient(metadata, 'packed', serverURL);
                let username       = generateRandomString();
                let displayName    = generateRandomName();
                return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            })
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-3

        Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's signature can not be verified, and check that serve returns an error

    `, () => {
        let webauthnClient = undefined;
        return getMDSMetadataForTestCase(serverURL, 'badSignature')
            .then((metadata) => {
                webauthnClient  = new window.CTAP.WebauthnClient(metadata, 'packed', serverURL);
                let username       = generateRandomString();
                let displayName    = generateRandomName();
                return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            })
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-4

        Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's certificate chain can not be verified, and check that serve returns an error

    `, () => {
        let webauthnClient = undefined;
        return getMDSMetadataForTestCase(serverURL, 'badCertificateChain')
            .then((metadata) => {
                webauthnClient  = new window.CTAP.WebauthnClient(metadata, 'packed', serverURL);
                let username       = generateRandomString();
                let displayName    = generateRandomName();
                return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            })
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-5

        Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's metadata service intermediate certificate is revoked, and check that serve returns an error

    `, () => {
        let webauthnClient = undefined;
        return getMDSMetadataForTestCase(serverURL, 'intermediateCertificateRevoked')
            .then((metadata) => {
                webauthnClient  = new window.CTAP.WebauthnClient(metadata, 'packed', serverURL);
                let username       = generateRandomString();
                let displayName    = generateRandomName();
                return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            })
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-6

        Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS who's metadata service leaf certificate is revoked, and check that serve returns an error

    `, () => {
        let webauthnClient = undefined;
        return getMDSMetadataForTestCase(serverURL, 'subjectCertificateRevoked')
            .then((metadata) => {
                webauthnClient  = new window.CTAP.WebauthnClient(metadata, 'packed', serverURL);
                let username       = generateRandomString();
                let displayName    = generateRandomName();
                return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            })
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })
})
