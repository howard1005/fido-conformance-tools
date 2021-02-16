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

        Server-ServerAuthenticatorAttestationResponse-Resp-5

        Test server processing "packed" FULL attestation

    `, function() {

    let attestation = "direct";

    let serverURL = window.config.test.serverURL;

    let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements["Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator"], 'packed', serverURL);

    this.timeout(30000);
    this.retries(3);    

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation, and check that server succeeds

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


    it(`P-2

        Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation that contains chain that links to the root certificate in the metadata in it's response, and check that server succeeds

    `, () => {
        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements["Virtual Secp256R1 Multiple Root Certificates FIDO2 Conformance Testing CTAP2 Authenticator"], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'intermediate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with fmt set to an unknown attestation format, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'fmtUnknown': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-2

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, and with attStmt.sig contains a signature that can not be verified, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'sigUnverifiable': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-3

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt missing "x5c" field, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-4

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c is not of type ARRAY, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-5

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c is an empty ARRAY, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cEmpty': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-6

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains a leaf certificate that is expired, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cLeafExpired': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-7

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains a leaf certificate that is not yet started, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cLeafNotStarted': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-8

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains a leaf certificate algorithm does not equal to the one that is specified in MetadataStatement, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cLeafAlgorithmNotInMetadata': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-9

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains certificate chain, that can not be verified, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cUnverifiableChain': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-10

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c containing full chain, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cFullChain': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-11

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c containing full chain, that is not correctly ordered, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cUnorderedChain': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-12

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c contains expired intermediate certificate, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cIntermediateExpired': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-13

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with signature that can not be verified by the public key extracted from leaf certificate, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cSigNotVerifiableByPKFromCert': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-14

        Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with signature that is generated using new credential private key, and not attestation batch private key, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'x5cSigMadeByRegistrationKeypair': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })
})