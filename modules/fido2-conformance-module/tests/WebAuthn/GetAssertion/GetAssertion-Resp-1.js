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

        WebAuthn-Platform-GetAssertion-Resp-1

        Test GetAssertion response structure

    `, function() {


    let GetAssertionResp = undefined;
    let challenge        = undefined;
    before(function() {
        this.timeout(120000);

        let publicKey         = generateGoodWebAuthnMakeCredential();
        publicKey.attestation = 'direct';

        return navigator.credentials.create({ publicKey })
            .then((response) => Promise.all([window.navigator.fido.webauthn.decodeToJSON(response.response.attestationObject),
                                             window.navigator.fido.webauthn.decodeToObjectStruct(response.response.attestationObject)]))
            .then((response) => {
                let attestationObject       = response[0];
                let attestationObjectStruct = response[1];

                let authData = parseAuthData(attestationObjectStruct.authData);

                let publicKey = generateGoodWebAuthnGetAssertion(authData.credId);
                challenge     = publicKey.challenge;
                return navigator.credentials.get({ publicKey })
            })
            .then((response) => {
                GetAssertionResp = response;
            })
    })    
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid GetAssertion request, wait for the UserAssertion, and check that: 
            (a) UserAssertion was successfull
            (b) UserAssertion.rawId is of type BufferSource, and is at least 16 bytes long
            (c) UserAssertion.id is set to base64url encoding of UserAssertion.rawId
            (d) UserAssertion.type is set to "public-key"
            (e) UserAssertion.response is of type Dictionary
            (f) UserAssertion.response.clientDataJSON is of type BufferSource
            (g) UserAssertion.response.authenticatorData is of type BufferSource
            (g) UserAssertion.response.signature is of type BufferSource
            (g) UserAssertion.response.userHandle is of type BufferSource
            (h) UserAssertion.getClientExtensionResults is of type Dictionary

    `, () => {
        assert.isDefined(GetAssertionResp.rawId, 'GetAssertionResp missing rawId field!');
        assert.strictEqual(type(GetAssertionResp.rawId), 'ArrayBuffer', 'Expected rawId to be of type BufferSource!');
        assert.isAtLeast(GetAssertionResp.rawId.byteLength, 16, 'Credential ID must be at least 16 bytes long!');

        assert.isDefined(GetAssertionResp.id, 'GetAssertionResp missing id field!');
        assert.strictEqual(type(GetAssertionResp.id), 'String', 'Expected id to be of type DOMString!');
        assert.strictEqual(base64url.encode(GetAssertionResp.rawId), GetAssertionResp.id, 'Expected base64url(rawId) to strictly equal to id!');

        assert.isDefined(GetAssertionResp.type, 'GetAssertionResp missing type field!');
        assert.strictEqual(type(GetAssertionResp.type), 'String', 'Expected type to be of type DOMString!');
        assert.strictEqual(GetAssertionResp.type, 'public-key', 'Expected type to be set to "public-key"!');

        assert.isDefined(GetAssertionResp.response, 'GetAssertionResp missing response field!');
        assert.isTrue(GetAssertionResp.response instanceof Object, 'Object', 'Expected GetAssertionResp to be of type Dictionary!');

        assert.isDefined(GetAssertionResp.response.clientDataJSON, 'GetAssertionResp.response missing clientDataJSON field!');
        assert.strictEqual(type(GetAssertionResp.response.clientDataJSON), 'ArrayBuffer', 'Expected clientDataJSON to be of type BufferSource!');

        assert.isDefined(GetAssertionResp.response.authenticatorData, 'GetAssertionResp.response missing authenticatorData field!');
        assert.strictEqual(type(GetAssertionResp.response.authenticatorData), 'ArrayBuffer', 'Expected authenticatorData to be of type BufferSource!');

        assert.isDefined(GetAssertionResp.response.signature, 'GetAssertionResp.response missing signature field!');
        assert.strictEqual(type(GetAssertionResp.response.signature), 'ArrayBuffer', 'Expected signature to be of type BufferSource!');

        if(GetAssertionResp.response.userHandle && GetAssertionResp.response.userHandle !== null) {
            assert.isDefined(GetAssertionResp.response.userHandle, 'GetAssertionResp.response missing userHandle field!');
            assert.strictEqual(type(GetAssertionResp.response.userHandle), 'ArrayBuffer', 'Expected userHandle to be of type BufferSource!');
        }

        assert.isDefined(GetAssertionResp.getClientExtensionResults, 'GetAssertionResp missing getClientExtensionResults field!');
        assert.isTrue(GetAssertionResp.getClientExtensionResults instanceof Object, 'Expected getClientExtensionResults to be of type Dictionary!');
    })

    it(`P-2

        Decode UserAssertion.response.clientDataJSON to JSON dictionary as CollectedClientData, and check that:
            (a) CollectedClientData.type is of type DOMString and is set to "webauthn.get"
            (b) CollectedClientData.challenge is of type DOMString and is set to base64url encoding of request challenge
            (c) CollectedClientData.origin is of type DOMString and is set to fully qualified origin of the requester

    `, () => {
        let JSONString = arrayBufferToString(GetAssertionResp.response.clientDataJSON);
        let CollectedClientData = JSON.parse(JSONString)

        assert.isDefined(CollectedClientData.type, 'CollectedClientData missing type field!');
        assert.strictEqual(type(CollectedClientData.type), 'String', 'CollectedClientData.type MUST be of type DOMString!');
        assert.strictEqual(CollectedClientData.type, 'webauthn.get', 'For GetAssertion request, CollectedClientData.type must be set to "webauthn.get"!');

        assert.isDefined(CollectedClientData.challenge, 'CollectedClientData missing challenge field!');
        assert.strictEqual(type(CollectedClientData.challenge), 'String', 'CollectedClientData.challenge MUST be of challenge DOMString!');
        assert.strictEqual(CollectedClientData.challenge, base64url.encode(challenge), 'For GetAssertion request, CollectedClientData.challenge must be set to base64url encoded challenge buffer!');

        assert.isDefined(CollectedClientData.origin, 'CollectedClientData missing origin field!');
        assert.strictEqual(type(CollectedClientData.origin), 'String', 'CollectedClientData.origin MUST be of origin DOMString!');
        assert.strictEqual(CollectedClientData.origin, location.origin, 'For GetAssertion request, CollectedClientData.origin must be set to fully qualified origin of the requester');
    })
})