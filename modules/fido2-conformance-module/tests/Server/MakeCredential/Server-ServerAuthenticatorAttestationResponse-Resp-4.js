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

        Server-ServerAuthenticatorAttestationResponse-Resp-4

        Test server support of the authentication algorithms

    `, function() {

    let serverURL = window.config.test.serverURL;

    this.timeout(30000);
    this.retries(3);

/* ----- POSITIVE TESTS ----- */

    it(`P-1

       OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW" algorithm, and check that server succeeds

       [AWAITS IANA]

    `)

    it(`P-2

        OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PSS_SHA256_RAW" algorithm, and check that server succeeds

    `, function() {
        if(!window.config.test.fido2OptionalAlgorithms.ALG_SIGN_RSASSA_PSS_SHA256_RAW)
            this.skip();

        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSAPSS SHA256 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-3

        OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PSS_SHA384_RAW" algorithm, and check that server succeeds

    `, function() {
        if(!window.config.test.fido2OptionalAlgorithms.ALG_SIGN_RSASSA_PSS_SHA384_RAW)
            this.skip();

        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSAPSS SHA384 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-4

       OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PSS_SHA512_RAW" algorithm, and check that server succeeds

    `, function() {
        if(!window.config.test.fido2OptionalAlgorithms.ALG_SIGN_RSASSA_PSS_SHA512_RAW)
            this.skip();

        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSAPSS SHA512 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-5

        Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW" algorithm, and check that server succeeds

    `, function() {
        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSA PCKS1.5 SHA256 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-6

       OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW" algorithm, and check that server succeeds

    `, function() {
        if(!window.config.test.fido2OptionalAlgorithms.ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW)
            this.skip();

        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSA PCKS1.5 SHA384 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-7

        OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW" algorithm, and check that server succeeds

    `, function() {
        if(!window.config.test.fido2OptionalAlgorithms.ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW)
            this.skip();

        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSA PCKS1.5 SHA512 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-8

       Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW" algorithm, and check that server succeeds

    `, function() {
        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual RSA PCKS1.5 SHA1 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-9

        Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW" algorithm, and check that server succeeds

    `, function() {
        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-10

        OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW" algorithm, and check that server succeeds

    `, function() {
        if(!window.config.test.fido2OptionalAlgorithms.ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW)
            this.skip();

        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual Secp384r1 SHA384 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-11

       OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW" algorithm, and check that server succeeds

    `, function() {
        if(!window.config.test.fido2OptionalAlgorithms.ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW)
            this.skip();

        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual Secp521r1 SHA512 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    it(`P-12

        OPTIONAL: Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_ED25519_EDDSA_SHA512_RAW" algorithm, and check that server succeeds

    `, function() {
        if(!window.config.test.fido2OptionalAlgorithms.ALG_SIGN_ED25519_EDDSA_SHA512_RAW)
            this.skip();

        let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual FIDO2 EdDSA25519 SHA512 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response, {'forceSurrogate': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

/* ----- NEGATIVE TESTS ----- */
})