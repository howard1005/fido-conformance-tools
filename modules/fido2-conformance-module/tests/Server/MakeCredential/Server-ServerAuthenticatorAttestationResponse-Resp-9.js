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

        Server-ServerAuthenticatorAttestationResponse-Resp-9

        Test server processing "tpm" attestation

    `, function() {

    let serverURL = window.config.test.serverURL;
    let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSA PKCS 1.5 SHA256 FIDO2 Conformance Testing CTAP2 Authenticator with TPM Attestation'], 'tpm', serverURL);

    this.timeout(30000);
    this.retries(3);

/* ----- POSITIVE TESTS ----- */

    it(`P-1

        Send a valid ServerAuthenticatorAttestationResponse with "tpm" attestation for SHA-256, and check that server succeeds

    `, () => {
        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSA PKCS 1.5 SHA256 FIDO2 Conformance Testing CTAP2 Authenticator with TPM Attestation'], 'tpm', serverURL);

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

        Send a valid ServerAuthenticatorAttestationResponse with "tpm" attestation for SHA-1, and check that server succeeds

    `, () => {
        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSA PKCS 1.5 SHA1 FIDO2 Conformance Testing CTAP2 Authenticator with TPM Attestation'], 'tpm', serverURL);

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

    /* 
        So the name is concatenation of nameAlg[2byte] and hash structure[n-bytes].

        The confusion comes from the fact TPMS_CERTIFY_INFO contains name field that contains name of the TPMT_PUBLIC. But in the same time TPMT_PUBLIC contain nameAlg field that contains algorithm identifier for calculating authPolicy. There two both use nameAlg, but they can be different.

        For example:
        TPMT_PUBLIC.nameAlg = SHA-1;
        TPMT_PUBLIC.authPolicy = hashTPMT_PUBLIC.nameAlg

        nameAlg = SHA-256
        TPMS_CERTIFY_INFO.name = nameAlg || hashnameAlg
    */
    it(`P-3

        Send a valid ServerAuthenticatorAttestationResponse with "tpm" attestation pubArea.nameAlg is not matching algorithm used for generate attested.name, and check that server succeeds

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'tpmPubAreaNameAlgNotMatchingCertInfo': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

  
/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send ServerAuthenticatorAttestationResponse with "tpm" attestation has incorrect certificate order, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'tpmAttsCertificateOrder': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-2

        Send ServerAuthenticatorAttestationResponse with "tpm" attestation certInfo.extraData is not set to a valid hash of attToBeSigned, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'tpmCertInfoInvalidAttToBeSignedHash': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-3

        Send ServerAuthenticatorAttestationResponse with "tpm" attestation certInfo.magic is not set to TPM_GENERATED_VALUE(0xff544347), and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'tpmCertInfoInvalidMagic': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })


    it(`F-4

        Send ServerAuthenticatorAttestationResponse with "tpm" attestation pubArea.unique is not set to newly generated public key, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'tpmPubAreaInvalidUnique': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })
})