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

        Server-ServerAuthenticatorAssertionResponse-Resp-2

        Test server processing CollectClientData

    `, function() {
    let serverURL        = window.config.test.serverURL;
    let username         = generateRandomString();
    let displayName      = generateRandomName();
    let attestation      = 'direct';
    let webauthnClient   = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
    let userVerification = 'required';
    let ServerPublicKeyCredentialGetOptionsResponse = undefined;
    before(function() {
        this.timeout(30000);

        return getMakeCredentialsChallenge({username, displayName, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
            .then(() => {
                return getGetAssertionChallenge({username, userVerification})
            })
            .then((response) => {
                ServerPublicKeyCredentialGetOptionsResponse = response;
            })
    })

    this.timeout(30000);
    this.retries(3);

/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send ServerAuthenticatorAssertionResponse with clientDataJSON struct missing "type" field

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONTypeMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-2

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.type is not of type DOMString

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONTypeInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-3

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.type is empty DOMString

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONTypeEmpty': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-4

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.type is not set to "webauthn.get"

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONTypeNotGet': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-5

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.type is set to "webauthn.create"

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONTypeCreate': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-6

        Send ServerAuthenticatorAssertionResponse with clientDataJSON struct missing "challenge" field

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONChallengeMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-7

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.challenge is not of type DOMString

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONChallengeInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-8

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.challenge is empty DOMString

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONChallengeEmpty': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-9

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.challenge is not base64url encoded

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONChallengeBadEncoding': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-10

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.challenge is not set to request.challenge

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONChallengeNotMatching': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-11

        Send ServerAuthenticatorAssertionResponse with clientDataJSON struct missing "origin" field

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONOriginMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-12

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.origin is not of type DOMString

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONOriginInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-13

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.origin is empty DOMString

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONOriginEmpty': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-14

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.origin is not set to the origin

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONOriginNotMatching': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-15

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.tokenBinding is not of type Object

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONTokenBindingInvalid': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-16

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.tokenBinding missing status field

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONTokenBindingStatusFieldMissing': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-17

        Send ServerAuthenticatorAssertionResponse with clientDataJSON.tokenBinding.status is not set to either of present, supported or not-supported

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'clientDataJSONTokenBindingStatusFieldIncorrect': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })
})