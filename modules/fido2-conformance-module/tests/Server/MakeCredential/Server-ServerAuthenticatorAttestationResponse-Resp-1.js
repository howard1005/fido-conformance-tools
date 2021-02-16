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

    let attestation     = "direct";

    let serverURL = window.config.test.serverURL;

    let webauthnClient  = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements["Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator"], 'packed', serverURL);

    this.timeout(30000);
    this.retries(3);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Get PublicKeyCredentialCreationOptions, generate a valid response(with for example packed attestation). Get another one of PublicKeyCredentialCreationOptions for the same username as in previous request, and check that it's have "excludeCredentials" field and:
                (a) it's of type Array
                (b) it's not empty
                (c) each member is of type PublicKeyCredentialDescriptor
                (d) it contains PublicKeyCredentialDescriptor, with "type" set to "public-key", and "id" set to base64url encoded credId from the previous registration

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        let credId         = undefined;
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                credId = response.id
                return sendAttestationResponse(response)
            })
            .then(() => {
                return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            })
            .then((response) => {
                assert.isDefined(response.excludeCredentials, 'Response is missing "excludeCredentials" field!');
                assert.isArray(response.excludeCredentials, 'Response.excludeCredentials is not of type Sequence!');
                assert.isNotEmpty(response.excludeCredentials, 'Response.excludeCredentials is empty!');

                for(let cred of response.excludeCredentials) {
                    if(cred.id === credId)
                        return

                    throw new Error(`ExcludeCredentials do not contain expected credential! Expected "${JSON.stringify(response.excludeCredentials)}" to include "${JSON.stringify({'type':'public-key', 'id': credId})}"!`);
                }
            })
    })

/* ----- POSITIVE TESTS ----- */
    it(`F-1

        Send ServerAuthenticatorAttestationResponse that is missing "id" field and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.id = undefined;
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-2

        Send ServerAuthenticatorAttestationResponse with "id" field is NOT of type DOMString, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.id = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-3

        Send ServerAuthenticatorAttestationResponse with "id" is not base64url encode, and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.id = base64.encode(base64url.decode(response.id)) + '==';
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-4

        Send ServerAuthenticatorAttestationResponse that is missing "type" field and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.type = undefined;
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-5

        Send ServerAuthenticatorAttestationResponse with "type" field is NOT of type DOMString and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.type = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-6

        Send ServerAuthenticatorAttestationResponse with "type" is not set to "public-key", and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.type = "avocado-toast";
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-7

        Send ServerAuthenticatorAttestationResponse that is missing "response" field and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.response = undefined
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-8

        Send ServerAuthenticatorAttestationResponse with "response" field is NOT of type Object and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.response = generateRandomTypeExcluding('object');
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-9

        Send ServerAuthenticatorAttestationResponse that is missing "response.clientDataJSON" and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.response.clientDataJSON = undefined;
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-10

        Send ServerAuthenticatorAttestationResponse with response.clientDataJSON is not of type DOMString and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.response.clientDataJSON = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-11

        Send ServerAuthenticatorAttestationResponse with response.clientDataJSON is empty DOMString and check that server returns an error
    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.response.clientDataJSON = '';
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-12

        Send ServerAuthenticatorAttestationResponse that is missing response.attestationObject and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.response.attestationObject = undefined;
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-13

        Send ServerAuthenticatorAttestationResponse with response.attestationObject is not of type DOMString and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                response.response.attestationObject = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })

    it(`F-14

        Send ServerAuthenticatorAttestationResponse with response.attestationObject is empty DOMString and check that server returns an error

    `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        return getMakeCredentialsChallenge({'displayName': displayName, 'username':username, 'attestation': 'direct'})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {   
                response.response.attestationObject = '';
                return expectPromiseToFail(sendAttestationResponse(response))
            })
    })
})