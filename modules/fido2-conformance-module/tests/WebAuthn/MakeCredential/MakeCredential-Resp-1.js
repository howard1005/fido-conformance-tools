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

        WebAuthn-Platform-MakeCred-Resp-1

        Test MakeCredential AttestationResponse

    `, function() {

    beforeEach(function() {
        this.timeout(10000)
        return TimeoutPromise(2000)
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid MakeCredential request, wait for the AttestationResponse, and check that: 
            (a) AttestationResponse was successfull
            (b) AttestationResponse.rawId is of type BufferSource, and is at least 16 bytes long
            (c) AttestationResponse.id is set to base64url encoding of AttestationResponse.rawId
            (d) AttestationResponse.type is set to "public-key"
            (e) AttestationResponse.response is of type Dictionary
            (f) AttestationResponse.response.clientDataJSON is of type BufferSource
            (g) AttestationResponse.response.attestationObject is of type BufferSource
            (h) AttestationResponse.getClientExtensionResults is of type Dictionary

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
        return navigator.credentials.create({ publicKey })
            .then((AttestationResponse) => {
                assert.isDefined(AttestationResponse.rawId, 'AttestationResponse missing rawId field!');
                assert.strictEqual(type(AttestationResponse.rawId), 'ArrayBuffer', 'Expected rawId to be of type BufferSource!');
                assert.isAtLeast(AttestationResponse.rawId.byteLength, 16, 'Credential ID must be at least 16 bytes long!');

                assert.isDefined(AttestationResponse.id, 'AttestationResponse missing id field!');
                assert.strictEqual(type(AttestationResponse.id), 'String', 'Expected id to be of type DOMString!');
                assert.strictEqual(base64url.encode(AttestationResponse.rawId), AttestationResponse.id, 'Expected base64url(rawId) to strictly equal to id!');

                assert.isDefined(AttestationResponse.type, 'AttestationResponse missing type field!');
                assert.strictEqual(type(AttestationResponse.type), 'String', 'Expected type to be of type DOMString!');
                assert.strictEqual(AttestationResponse.type, 'public-key', 'Expected type to be set to "public-key"!');

                assert.isDefined(AttestationResponse.response, 'AttestationResponse missing response field!');
                assert.isTrue(AttestationResponse.response instanceof Object, 'Object', 'Expected AttestationResponse to be of type Dictionary!');

                assert.isDefined(AttestationResponse.response.clientDataJSON, 'AttestationResponse.response missing clientDataJSON field!');
                assert.strictEqual(type(AttestationResponse.response.clientDataJSON), 'ArrayBuffer', 'Expected clientDataJSON to be of type BufferSource!');

                assert.isDefined(AttestationResponse.response.attestationObject, 'AttestationResponse.response missing attestationObject field!');
                assert.strictEqual(type(AttestationResponse.response.attestationObject), 'ArrayBuffer', 'Expected attestationObject to be of type BufferSource!');

                assert.isDefined(AttestationResponse.getClientExtensionResults, 'AttestationResponse missing getClientExtensionResults field!');
                assert.isTrue(AttestationResponse.getClientExtensionResults instanceof Object, 'Expected getClientExtensionResults to be of type Dictionary!');
            })
    })

    it(`P-2

        Decode AttestationResponse.response.clientDataJSON to JSON dictionary as CollectedClientData, and check that:
            (a) CollectedClientData.type is of type DOMString and is set to "webauthn.create"
            (b) CollectedClientData.challenge is of type DOMString and is set to base64url encoding of request challenge
            (c) CollectedClientData.origin is of type DOMString and is set to fully qualified origin of the requester

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();

        return navigator.credentials.create({ publicKey })
            .then((AttestationResponse) => {
                let JSONString = arrayBufferToString(AttestationResponse.response.clientDataJSON);
                let CollectedClientData = JSON.parse(JSONString)

                assert.isDefined(CollectedClientData.type, 'CollectedClientData missing type field!');
                assert.strictEqual(type(CollectedClientData.type), 'String', 'CollectedClientData.type MUST be of type DOMString!');
                assert.strictEqual(CollectedClientData.type, 'webauthn.create', 'For MakeCredential request, CollectedClientData.type must be set to "webauthn.create"!');

                assert.isDefined(CollectedClientData.challenge, 'CollectedClientData missing challenge field!');
                assert.strictEqual(type(CollectedClientData.challenge), 'String', 'CollectedClientData.challenge MUST be of challenge DOMString!');
                assert.strictEqual(CollectedClientData.challenge, base64url.encode(publicKey.challenge), 'For MakeCredential request, CollectedClientData.challenge must be set to base64url encoded challenge buffer!');

                assert.isDefined(CollectedClientData.origin, 'CollectedClientData missing origin field!');
                assert.strictEqual(type(CollectedClientData.origin), 'String', 'CollectedClientData.origin MUST be of origin DOMString!');
                assert.strictEqual(CollectedClientData.origin, location.origin, 'For MakeCredential request, CollectedClientData.origin must be set to fully qualified origin of the requester');
            })
    })
})
