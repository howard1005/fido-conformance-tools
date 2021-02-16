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

        Server-ServerAuthenticatorAssertionResponse-Resp-1

        Test server processing ServerAuthenticatorAssertionResponse structure

    `, function() {
    let serverURL        = window.config.test.serverURL;
    let username         = generateRandomString();
    let displayName      = generateRandomName();
    let attestation      = 'direct';
    let webauthnClient   = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
    let userVerification = 'required';
    before(function() {
        this.timeout(30000);

        return getMakeCredentialsChallenge({username, displayName, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
    })

    this.timeout(30000);
    this.retries(3);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid ServerAuthenticatorAssertionResponse, and check that server succeeds

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                return sendAssertionResponse(response)
            })
    })

/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send ServerAuthenticatorAssertionResponse that is missing "id" field and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.id = undefined;
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-2

        Send ServerAuthenticatorAssertionResponse with "id" field is NOT of type DOMString, and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.id = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-3

        Send ServerAuthenticatorAssertionResponse with "id" is not base64url encode, and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.id = base64.encode(base64url.decode(response.id)) + '==';
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-4

        Send ServerAuthenticatorAssertionResponse that is missing "type" field and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.type = undefined;
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-5

        Send ServerAuthenticatorAssertionResponse with "type" field is NOT of type DOMString and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.type = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-6

        Send ServerAuthenticatorAssertionResponse with "type" is not set to "public-key", and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.type = "avocado-toast";
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-7

        Send ServerAuthenticatorAssertionResponse that is missing "response" field and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response = undefined
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-8

        Send ServerAuthenticatorAssertionResponse with "response" field is NOT of type Object and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response = generateRandomTypeExcluding('object');
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-9

        Send ServerAuthenticatorAssertionResponse that is missing "response.clientDataJSON" and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.clientDataJSON = undefined;
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-10

        Send ServerAuthenticatorAssertionResponse with response.clientDataJSON is not of type DOMString and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.clientDataJSON = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-11

        Send ServerAuthenticatorAssertionResponse with response.clientDataJSON is empty DOMString and check that server returns an error
    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.clientDataJSON = '';
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-12

        Send ServerAuthenticatorAssertionResponse that is missing response.authenticatorData and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.authenticatorData = undefined;
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-13

        Send ServerAuthenticatorAssertionResponse with response.authenticatorData is not of type DOMString and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.authenticatorData = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-14

        Send ServerAuthenticatorAssertionResponse with response.authenticatorData is not base64url encoded and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.authenticatorData = base64.encode(base64url.decode(response.response.authenticatorData)) + '==';
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-15

        Send ServerAuthenticatorAssertionResponse with response.authenticatorData is empty DOMString and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {   
                response.response.authenticatorData = '';
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-16

        Send ServerAuthenticatorAssertionResponse that is missing response.signature and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.signature = undefined;
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-17

        Send ServerAuthenticatorAssertionResponse with response.signature is not of type DOMString and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.signature = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-18

        Send ServerAuthenticatorAssertionResponse with response.signature is not base64url encoded and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.signature = base64.encode(base64url.decode(response.response.signature)) + '==';
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-19

        Send ServerAuthenticatorAssertionResponse with response.signature is empty DOMString and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {   
                response.response.signature = '';
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-20

        Send ServerAuthenticatorAssertionResponse with response.signature containing unverifiable signature

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                let signatureBuffer = base64url.decode(response.response.signature);
                let randomIndex     = generateSecureRandomInt(0, signatureBuffer.length - 1);
                signatureBuffer[randomIndex] += 1;
                response.response.signature = base64url.encode(signatureBuffer);

                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-21

        Send ServerAuthenticatorAssertionResponse with response.userHandle is not of type DOMString and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                response.response.userHandle = generateRandomTypeExcluding('string');
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    // it(`F-23

    //     Successfully register credential with requireResidentKey set to true. Send ServerAuthenticatorAssertionResponse with response.userHandle is empty DOMString and check that server returns an error

    // `, () => {
    //     let attestation = 'direct';
    //     let authenticatorSelection = {
    //         'requireResidentKey': true,
    //         'authenticatorAttachment': 'cross-platform',
    //         'userVerification': 'preferred'
    //     }

    //     return getMakeCredentialsChallenge({username, displayName, attestation, authenticatorSelection})
    //         .then((response) => {
    //             return webauthnClient.createCredential(response)
    //         })
    //         .then((response) => {
    //             return sendAttestationResponse(response)
    //         })
    //     return getGetAssertionChallenge({username})
    //         .then((response) => {
    //             return webauthnClient.requestAssertion(response)
    //         })
    //         .then((response) => {   
    //             response.response.userHandle = '';
    //             return expectPromiseToFail(sendAssertionResponse(response))
    //         })
    // })
})