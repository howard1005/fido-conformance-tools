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

        Server-ServerAuthenticatorAssertionResponse-Resp-3

        Test server processing authenticatorData

    `, function() {
    let serverURL   = window.config.test.serverURL;
    let username    = generateRandomString();
    let displayName = generateRandomName();
    let attestation = 'direct';
    let extensions  = {
        'example.extension': 'In a hole in the ground there lived a hobbit'
    }

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

    it(`P-1

         Send a valid ServerAuthenticatorAssertionResponse, for the authenticator that does not support counter(counter is always 0), and check that server succeeds

     `, () => {
        let username       = generateRandomString();
        let displayName    = generateRandomName();
        let webauthnClient = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
         return getMakeCredentialsChallenge({username, displayName, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response, {'authenticatorDataContainsCounterSetToZero': true})
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
            .then((response) => {
                return getGetAssertionChallenge({username})
            })
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataContainsCounterSetToZero': true})
            })
            .then((response) => {
                return sendAssertionResponse(response)
            })
    })

    it(`P-2

        Send a valid ServerAuthenticatorAssertionResponse with authenticatorData.flags.UV is set, for userVerification set to "required", and check that server succeeds

    `, () => {
        let userVerification = 'required';

        return getGetAssertionChallenge({username, userVerification})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataFlagsUVisTRUE': true})
            })
            .then((response) => {
                return sendAssertionResponse(response)
            })
    })

    it(`P-3

        Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP is set, for userVerification set to "required", and check that server succeeds

    `, () => {
        let userVerification = 'required';

        return getGetAssertionChallenge({username, userVerification})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataFlagsUPisTRUE': true, 'authenticatorDataFlagsUVisTRUE': true})
            })
            .then((response) => {
                return sendAssertionResponse(response)
            })
    })

    it(`P-4

        Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "preferred", and check that server succeeds

    `, () => {
        let userVerification = 'preferred';

        return getGetAssertionChallenge({username, userVerification})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataFlagsUPisFALSE': true, 'authenticatorDataFlagsUVisFALSE': true})
            })
            .then((response) => {
                return sendAssertionResponse(response)
            })
    })

    it(`P-5

        Send a valid ServerAuthenticatorAssertionResponse with authenticatorData.flags.UP is set, despite requested userVerification set to "discouraged", and check that server succeeds

    `, () => {
        let userVerification = 'discouraged';

        return getGetAssertionChallenge({username, userVerification})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataFlagsUPisTRUE': true})
            })
            .then((response) => {
                return sendAssertionResponse(response)
            })
    })

    it(`P-6

        Send a valid ServerAuthenticatorAssertionResponse with authenticatorData.flags.UV is set, despite requested userVerification set to "discouraged", and check that server succeeds

    `, () => {
        let userVerification = 'discouraged';

        return getGetAssertionChallenge({username, userVerification})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataFlagsUVisTRUE': true})
            })
            .then((response) => {
                return sendAssertionResponse(response)
            })
    })

    it(`P-7

        Send a valid ServerAuthenticatorAssertionResponse both authenticatorData.flags.UV and authenticatorData.flags.UP are not set, for userVerification set to "discouraged", and check that server succeeds

    `, () => {
        let userVerification = 'discouraged';

        return getGetAssertionChallenge({username, userVerification })
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataFlagsUPisFALSE': true, 'authenticatorDataFlagsUVisFALSE': true})
            })
            .then((response) => {
                return sendAssertionResponse(response)
            })
    })

    it(`P-8

        Send a valid ServerAuthenticatorAssertionResponse with authenticatorData contains extension data, and ED is set to true, and check that server accepts the response

    `, () => {
        return getGetAssertionChallenge({username, extensions})
            .then((response) => {
                return webauthnClient.requestAssertion(response)
            })
            .then((response) => {
                return sendAssertionResponse(response)
            })
    })

/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send ServerAuthenticatorAssertionResponse with authenticatorData contains leftover bytes, and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataContainsLeftoverBytes': true})
            })
            .then((response) => {   
                let authenticatorDataBuffer = base64url.decode(response.response.authenticatorData);
                authenticatorDataBuffer = mergeArrayBuffers(authenticatorDataBuffer, generateRandomBuffer(2));

                response.response.authenticatorData = base64url.encode(authenticatorDataBuffer);
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-2

        Send ServerAuthenticatorAssertionResponse with authenticatorData.rpIdHash contains an invalid hash, and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataContainsInvalidRPIdHash': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-3

        Send ServerAuthenticatorAssertionResponse with authenticatorData.clientDataHash contains an invalid hash, and check that server returns an error

    `, () => {
        return getGetAssertionChallenge({username})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataContainsInvalidClientDataHash': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-4

        For authenticator that supports counter: Send ServerAuthenticatorAssertionResponse with authenticatorData.counter is not increased, and check that server returns an error
 
    `, () => {
        let webauthnClient   = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);

        let username    = generateRandomString();
        let displayName = generateRandomName();

        return getMakeCredentialsChallenge({username, displayName, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
            .then(() => {
                return getGetAssertionChallenge({username})
            })
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataCounterIsNotIncreased': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })

    it(`F-5

        Send a valid ServerAuthenticatorAssertionResponse with only authenticatorData.flags.UP is set, for userVerification set to "required", and check that server returns an error

    `, () => {
        let userVerification = 'required';

        return getGetAssertionChallenge({username, userVerification})
            .then((response) => {
                return webauthnClient.requestAssertion(response, {'authenticatorDataFlagsUPisTRUE': true})
            })
            .then((response) => {
                return expectPromiseToFail(sendAssertionResponse(response))
            })
    })
})