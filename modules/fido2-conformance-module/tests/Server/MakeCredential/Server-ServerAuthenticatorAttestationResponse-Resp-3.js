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

        Server-ServerAuthenticatorAttestationResponse-Resp-3

        Test server processing AttestationObject

    `, function() {

    let attestation = "direct";
    let extensions  = {
        'example.extension': 'In a hole in the ground there lived a hobbit'
    }

    let serverURL = window.config.test.serverURL;
 

    let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements["Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator"], 'packed', serverURL);

    this.timeout(30000);
    this.retries(3);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send "packed" ServerAuthenticatorAttestationResponse with attestationObject.authData contains extension data, and ED is set to true, and check that server accepts the response

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation, extensions})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })
/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send ServerAuthenticatorAttestationResponse with attestationObject is not a valid CBOR MAP, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.response.attestationObject = generateRandomString() + response.response.attestationObject;
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-2

        Send ServerAuthenticatorAttestationResponse with attestationObject is missing "fmt" field, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'fmtMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-3

        Send ServerAuthenticatorAttestationResponse with attestationObject.fmt field is not of type String, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'fmtInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-4

        Send ServerAuthenticatorAttestationResponse with attestationObject is missing "attStmt" field, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'attStmtMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-5

        Send ServerAuthenticatorAttestationResponse with attestationObject.attStmt is not of type MAP, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'attStmtInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-6

        Send ServerAuthenticatorAttestationResponse with attestationObject is missing "authData" field, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'authDataMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-7

        Send ServerAuthenticatorAttestationResponse with attestationObject.authData is not of type BYTE SEQUENCE, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'authDataInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-8

        Send ServerAuthenticatorAttestationResponse with attestationObject.authData is an empty BYTE SEQUENCE, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'authDataEmpty': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-9

        Send ServerAuthenticatorAttestationResponse with attestationObject.authData.flags AT is not set, but Attestation Data is presented, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'authDataFlagsATNotSetAttestationDataPresented': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-10

        Send ServerAuthenticatorAttestationResponse with attestationObject.authData.flags AT is not set, and Attestation Data is not presented, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'authDataFlagsATNotSetAttestationDataNotPresented': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-11

        Send ServerAuthenticatorAttestationResponse with attestationObject.authData.flags AT is set, and Attestation Data is not presented, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'authDataFlagsATSetAttestationDataNotPresented': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-12

        Send ServerAuthenticatorAttestationResponse with attestationObject.authData AttestationData contains leftover bytes, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'authDataAttestationDataContainsLeftoverBytes': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-13

        Send "packed" ServerAuthenticatorAttestationResponse with attStmt being an empty map, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'attStmtEmptyMap': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-14

        Send "packed" ServerAuthenticatorAttestationResponse with attStmt.alg is missing, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'attStmtAlgMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-15

        Send "packed" ServerAuthenticatorAttestationResponse with attStmt.alg is not of type Number, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'attStmtAlgInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-16

        Send "packed" ServerAuthenticatorAttestationResponse with attStmt.alg does not match Alg in metadata statement, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'attStmtAlgNotMatchingMetadata': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-17

        Send "packed" ServerAuthenticatorAttestationResponse with attStmt.sig is missing, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'attStmtSigMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-18

        Send "packed" ServerAuthenticatorAttestationResponse with attStmt.sig is not of type BYTE STRING, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'attStmtSigInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-19

        Send "packed" ServerAuthenticatorAttestationResponse with attStmt.sig set to empty BYTE STRING, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'attStmtSigEmpty': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })
})