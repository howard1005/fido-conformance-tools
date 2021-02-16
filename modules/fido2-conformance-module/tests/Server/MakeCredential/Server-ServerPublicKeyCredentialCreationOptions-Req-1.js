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

        Server-ServerPublicKeyCredentialCreationOptions-Req-1

        Test server generating ServerPublicKeyCredentialCreationOptionsRequest

    `, function() {

    let username       = generateRandomString();
    let displayName    = generateRandomName();

    let authenticatorSelection = {
        'requireResidentKey': false,
        'userVerification': 'preferred'
    }

    let extensions  = {
        'example.extension': true
    }

    let attestation = "direct";

    let ServerPublicKeyCredentialCreationOptionsResponse = undefined;
    before(function() {
        this.timeout(30000);
        
        return getMakeCredentialsChallenge({username, displayName, authenticatorSelection, attestation, extensions})
            .then((response) => {
                ServerPublicKeyCredentialCreationOptionsResponse = response;
            })
    })

    this.timeout(30000);
    this.retries(3);
    

/* ----- POSITIVE TESTS ----- */

    it(`P-1

        Get ServerPublicKeyCredentialCreationOptionsResponse, and check that:
            (a) response MUST contain "status" field, and it MUST be of type DOMString and set to "ok"
            (b) response MUST contain "errorMessage" field, and it MUST be of type DOMString and set to an empty string
            (c) response contains "user" field, of type Object and:
                (1) check that user.name is not missing, and is of type DOMString
                (2) check that user.displayName is not missing, and is of type DOMString
                (3) check that user.id is not missing, and is of type DOMString, and is not empty. It MUST be base64url encoded byte sequence, and is not longer than 64 bytes.
                (4) If user.icon is presented, check that it's is of type DOMString
            (d) response contains "rp" field, of type Object and:
                (1) check that rp.name is not missing, and is of type DOMString
                (2) check that rp.id is not missing, and is of type DOMString.
                (3) If rp.icon is presented, check that it's is of type DOMString
            (e) response contains "challenge" field, of type String, base64url encoded and not less than 16 bytes.
            (f) response contains "pubKeyCredParams" field, of type Array and:
                (1) each member MUST be of type Object
                (2) each member MUST contain "type" field of type DOMString
                (3) each member MUST contain "alg" field of type Number
                (4) MUST contain one member with type set to "public-key" and alg set to an algorithm that is supported by the authenticator
            (g) If response contains "timeout" field, check that it's of type Number and is bigger than 0
            (h) response contains "extensions" field, with "example.extension" key presented

    `, () => {
        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.status, 'Response is missing "status" field!');
        assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.status, 'Response.status MUST be of type DOMString!');
        assert.strictEqual(ServerPublicKeyCredentialCreationOptionsResponse.status, 'ok', 'Response.status MUST be set to "ok"!');

        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.errorMessage, 'Response is missing "errorMessage" field!');
        assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.errorMessage, 'Response.errorMessage MUST be of type DOMString!');
        assert.isEmpty(ServerPublicKeyCredentialCreationOptionsResponse.errorMessage, 'Response.errorMessage MUST be empty when OK!');

        /* ----- User ----- */
        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.user, 'Response is missing "user" field!');
        assert.isObject(ServerPublicKeyCredentialCreationOptionsResponse.user, 'Response.user MUST be of type Object!');
       
        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.user.name, 'Response.user missing "name" field!');
        assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.user.name, 'Response.user.name is not of type DOMString!');
        assert.isNotEmpty(ServerPublicKeyCredentialCreationOptionsResponse.user.name, 'Response.user.name is empty!');
        assert.strictEqual(ServerPublicKeyCredentialCreationOptionsResponse.user.name, username, 'Response.user.name is not set to requested name!');

        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.user.displayName, 'Response.user missing "displayName" field!');
        assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.user.displayName, 'Response.user.displayName is not of type DOMString!');
        assert.isNotEmpty(ServerPublicKeyCredentialCreationOptionsResponse.user.displayName, 'Response.user.displayName is empty!');
        assert.strictEqual(ServerPublicKeyCredentialCreationOptionsResponse.user.displayName, displayName, 'Response.user.displayName is not set to requested displayName!');

        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.user.id, 'Response.user missing "id" field!');
        assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.user.id, 'Response.user.id is not of type DOMString!');
        assert.isNotEmpty(ServerPublicKeyCredentialCreationOptionsResponse.user.id, 'Response.user.id is empty!');
        assert.match(ServerPublicKeyCredentialCreationOptionsResponse.user.id, /^[a-zA-Z0-9_-]+$/, 'Response.user.id MUST be base64URL(without padding) encoded!');

        if(ServerPublicKeyCredentialCreationOptionsResponse.user.icon) {
            assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.user.icon, 'Response.user.icon is not of type DOMString!');
            assert.isNotEmpty(ServerPublicKeyCredentialCreationOptionsResponse.user.icon, 'Response.user.icon is empty!');
        }

        /* ----- RP ----- */
        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.rp, 'Response is missing "rp" field!');
        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.rp.name, 'Response.rp missing "name" field!');
        assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.rp.name, 'Response.rp.name is not of type DOMString!');
        assert.isNotEmpty(ServerPublicKeyCredentialCreationOptionsResponse.rp.name, 'Response.rp.name is empty!');

        if(ServerPublicKeyCredentialCreationOptionsResponse.rp.id) {
            assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.rp.id, 'Response.rp.id is not of type DOMString!');
            assert.isNotEmpty(ServerPublicKeyCredentialCreationOptionsResponse.rp.id, 'Response.rp.id is empty!');
        }

        if(ServerPublicKeyCredentialCreationOptionsResponse.rp.icon) {
            assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.rp.icon, 'Response.rp.icon is not of type DOMString!');
            assert.isNotEmpty(ServerPublicKeyCredentialCreationOptionsResponse.rp.icon, 'Response.rp.icon is empty!');
        }

        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.challenge, 'Response is missing "challenge" field!');
        assert.isString(ServerPublicKeyCredentialCreationOptionsResponse.challenge, 'Response.challenge MUST be of type DOMString!');
        assert.match(ServerPublicKeyCredentialCreationOptionsResponse.challenge, /^[a-zA-Z0-9_-]+$/, 'Response.challenge MUST be base64URL(without padding) encoded!');
        assert.isAbove(ServerPublicKeyCredentialCreationOptionsResponse.challenge.length, 21, 'Response.challenge MUST be at least 16 bytes long!');

        assert.isDefined(ServerPublicKeyCredentialCreationOptionsResponse.pubKeyCredParams, 'Response is missing "pubKeyCredParams" field!');

        if(ServerPublicKeyCredentialCreationOptionsResponse.timeout) {
            assert.isNumber(ServerPublicKeyCredentialCreationOptionsResponse.timeout, 'Response.timeout MUST be of type Number!');
            assert.isAbove(ServerPublicKeyCredentialCreationOptionsResponse.timeout, 0, 'Response.timeout MUST bigger than 0!');
        }
        
        assert.strictEqual(ServerPublicKeyCredentialCreationOptionsResponse.attestation, attestation, `Response.attestation "${ServerPublicKeyCredentialCreationOptionsResponse}" was not set to the expected attestation "${attestation}"!`);

        assert.deepEqual(ServerPublicKeyCredentialCreationOptionsResponse.authenticatorSelection, authenticatorSelection, `Response.authenticatorSelection MUST be set to the requested authenticatorSelection! Expected "${JSON.stringify(ServerPublicKeyCredentialCreationOptionsResponse.authenticatorSelection)}" to equal "${JSON.stringify(authenticatorSelection)}"`);


        assert.deepEqual(ServerPublicKeyCredentialCreationOptionsResponse.extensions, extensions, `Response.extensions MUST be set to the requested extensions! Expected "${JSON.stringify(ServerPublicKeyCredentialCreationOptionsResponse.extensions)}" to equal "${JSON.stringify(extensions)}"`);

    })

    it(`P-2

        Request from server ServerPublicKeyCredentialCreationOptionsResponse with "none" attestation, and check that server, and check that ServerPublicKeyCredentialCreationOptionsResponse.attestation is set to "none"

    `, () => {        
        let attestation = "none";
        return getMakeCredentialsChallenge({username, displayName, authenticatorSelection, attestation})
            .then((response) => {
                assert.strictEqual(response.attestation, attestation, 'Client requestsed that server would set attestation to "none". Server has not returned attestation set to "none"!')
            })
    })

    it(`P-3

        Get two ServerPublicKeyCredentialCreationOptionsResponses, and check that challenge in Request1 is different to challenge in Request2

    `, () => {
        let challenge1 = undefined;
        let challenge2 = undefined;
        return getMakeCredentialsChallenge({username, displayName, authenticatorSelection, attestation})
            .then((response) => {
                challenge1 = response.challenge
                return getMakeCredentialsChallenge({username, displayName, authenticatorSelection, attestation})

            })
            .then((response) => {
                challenge2 = response.challenge
                assert.notStrictEqual(challenge1, challenge2, 'Server must generate a random challenge for each ServerPublicKeyCredentialCreationOptionsResponse!');
            })
    })
})