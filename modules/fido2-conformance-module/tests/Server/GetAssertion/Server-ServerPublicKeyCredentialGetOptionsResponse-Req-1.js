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

        Server-ServerPublicKeyCredentialGetOptionsResponse-Req-1

        Test server generating ServerPublicKeyCredentialGetOptionsResponse

    `, function() {
    let serverURL        = window.config.test.serverURL;
    let username         = generateRandomString();
    let webauthnClient   = new window.CTAP.WebauthnClient(config.manifesto.metadataStatements['Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator'], 'packed', serverURL);
    let userVerification = 'required';
    let ServerPublicKeyCredentialGetOptionsResponse = undefined;
    let extensions  = {
        'example.extension': true
    }

    before(function() {
        this.timeout(30000);
        let displayName = generateRandomName();
        let attestation = 'direct';

        return getMakeCredentialsChallenge({username, displayName, attestation})
            .then((response) => {
                return webauthnClient.createCredential(response)
            })
            .then((response) => {
                return sendAttestationResponse(response)
            })
            .then(() => {
                return getGetAssertionChallenge({username, userVerification, extensions})
            })
            .then((response) => {
                ServerPublicKeyCredentialGetOptionsResponse = response;
            })
    })

    this.timeout(30000);
    this.retries(3);
    

/* ----- POSITIVE TESTS ----- */

    it(`P-1

        Get ServerPublicKeyCredentialGetOptionsResponse, and check that:
            (a) response MUST contain "status" field, and it MUST be of type DOMString and set to "ok"
            (b) response MUST contain "errorMessage" field, and it MUST be of type DOMString and set to an empty string
            (c) response MUST contains "challenge" field, of type String, base64url encoded and not less than 16 bytes.
            (d) response MUST contains "extensions" field, of type Object, with "example.extension" set to a test string.
            (d) If response contains "timeout" field, check that it's of type Number and is bigger than 0
            (e) If response contains "rpId" field, it:
                (1) MUST be of type SVSString
                (2) MUST be HTTPS URL
                (3) MUST be either RP origin, or suffix of the origin
                (4) MUST include port if applies
            (f) response contains "allowCredentials" field, of type Array and:
                (1) each member MUST be of type Object
                (2) each member MUST contain "type" field of type DOMString
                (3) check that "id" field is not missing, and is of type DOMString, and is not empty. It MUST be base64url encoded byte sequence.
                (4) check that it's contain exactly one member, with type set to "public-key" and id is set to previously registered credID.
            (g) response.userVerification MUST be set to the requested "userVerification"

    `, () => {

        assert.isDefined(ServerPublicKeyCredentialGetOptionsResponse.challenge, 'Response is missing "challenge" field!');
        assert.isString(ServerPublicKeyCredentialGetOptionsResponse.challenge, 'Response.challenge MUST be of type DOMString!');
        assert.match(ServerPublicKeyCredentialGetOptionsResponse.challenge, /^[a-zA-Z0-9_-]+$/, 'Response.challenge MUST be base64URL(without padding) encoded!');
        assert.isAbove(ServerPublicKeyCredentialGetOptionsResponse.challenge.length, 21, 'Response.challenge MUST be at least 16 bytes long!');

        assert.isDefined(ServerPublicKeyCredentialGetOptionsResponse.extensions, 'Response is missing "extensions" field!');
        assert.isObject(ServerPublicKeyCredentialGetOptionsResponse.extensions, 'Response.extensions MUST be of type Dictionary!');
        assert.isDefined(ServerPublicKeyCredentialGetOptionsResponse.extensions['example.extension'], 'Response.extensions missing "example.extension" extension!');
        assert.strictEqual(ServerPublicKeyCredentialGetOptionsResponse.extensions['example.extension'], extensions['example.extension'], 'Response.extensions["example.extension"] does not match set value!');

        assert.isDefined(ServerPublicKeyCredentialGetOptionsResponse.status, 'Response is missing "status" field!');
        assert.isString(ServerPublicKeyCredentialGetOptionsResponse.status, 'Response.status MUST be of type DOMString!');
        assert.strictEqual(ServerPublicKeyCredentialGetOptionsResponse.status, 'ok', 'Response.status MUST be set to "ok"!');

        assert.isDefined(ServerPublicKeyCredentialGetOptionsResponse.errorMessage, 'Response is missing "errorMessage" field!');
        assert.isString(ServerPublicKeyCredentialGetOptionsResponse.errorMessage, 'Response.errorMessage MUST be of type DOMString!');
        assert.isEmpty(ServerPublicKeyCredentialGetOptionsResponse.errorMessage, 'Response.errorMessage MUST be empty when OK!');

        if(ServerPublicKeyCredentialGetOptionsResponse.timeout) {
            assert.isNumber(ServerPublicKeyCredentialGetOptionsResponse.timeout, 'Response.timeout MUST be of type Number!');
            assert.isAbove(ServerPublicKeyCredentialGetOptionsResponse.timeout, 0, 'Response.timeout MUST bigger than 0!');
        }

        if(ServerPublicKeyCredentialGetOptionsResponse.rpId) {
            // assert.isNumber(ServerPublicKeyCredentialGetOptionsResponse.timeout, 'Response.timeout MUST be of type Number!');
            // assert.isAbove(ServerPublicKeyCredentialGetOptionsResponse.timeout, 0, 'Response.timeout MUST bigger than 0!');
        }

        assert.isDefined(ServerPublicKeyCredentialGetOptionsResponse.allowCredentials, 'Response is missing "allowCredentials" field');
        assert.isArray(ServerPublicKeyCredentialGetOptionsResponse.allowCredentials, 'Response.allowCredentials MUST be of type SEQUENCE!');
        assert.strictEqual(ServerPublicKeyCredentialGetOptionsResponse.allowCredentials.length, 1, 'Response.allowCredentials MUST contain exactly one ServerPublicKeyCredentialDescriptor!');
        let cred = ServerPublicKeyCredentialGetOptionsResponse.allowCredentials[0];
        assert.isDefined(cred.type, 'ServerPublicKeyCredentialDescriptor is missing "type" field!');
        assert.isString(cred.type, 'ServerPublicKeyCredentialDescriptor.type MUST be of type DOMString!');
        assert.strictEqual(cred.type, 'public-key', 'ServerPublicKeyCredentialDescriptor.type MUST set to "public-key"');
        
        assert.isDefined(cred.id, 'ServerPublicKeyCredentialDescriptor is missing "id" field!');
        assert.isString(cred.id, 'ServerPublicKeyCredentialDescriptor.type  MUST be of type DOMString!');
        assert.match(cred.id, /^[a-zA-Z0-9_-]+$/, 'ServerPublicKeyCredentialDescriptor.id MUST be base64URL(without padding) encoded!');
        assert.isNotEmpty(cred.id, 'cred.id MUST not be empty!');

        assert.strictEqual(ServerPublicKeyCredentialGetOptionsResponse.userVerification, userVerification, `Response.userVerification MUST be set to the requested userVerification! Expected "${ServerPublicKeyCredentialGetOptionsResponse.userVerification}" to equal "${userVerification}"!`);

    })

    it(`P-2

        Get two ServerPublicKeyCredentialGetOptionsResponse, and check that challenge in Request1 is different to challenge in Request2

    `, () => {
        let challenge1 = undefined;
        let challenge2 = undefined;
        return getGetAssertionChallenge({username})
            .then((response) => {
                challenge1 = response.challenge
                return getGetAssertionChallenge({username})

            })
            .then((response) => {
                challenge2 = response.challenge
                assert.notStrictEqual(challenge1, challenge2, 'Server must generate a random challenge for each ServerPublicKeyCredentialCreationOptionsResponse!');
            })
    })
})