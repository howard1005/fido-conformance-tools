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
    let credId           = undefined;
    let cosePublicKey    = undefined;
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

                let authData  = parseAuthData(attestationObjectStruct.authData);
                credId        = authData.credId;
                cosePublicKey = authData.COSEPublicKey;
                let publicKey = generateGoodWebAuthnGetAssertion(credId);
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

        Send a valid GetAssertion request, wait for the UserAssertion. Decode "authenticatorData" field, and check that:
            (a) The length of authenticatorData is exactly 37 bytes
            (b) RPIDHASH is set to the the SHA256 hash of rpId
            (c) FLAGS.UV or/and FLAGS.UP are/is set
            (d) FLAGS.AT and FLAGS.ED are not set

    `, () => {
        assert.strictEqual(GetAssertionResp.response.authenticatorData.byteLength, 37, 'For GetAssertion response, with no extensions, authenticatorData must be exactly 37 bytes long!');

        let authData = parseAuthData(GetAssertionResp.response.authenticatorData);

        assert.isTrue(authData.flags.up || authData.flags.uv, 'For GetAssertion, User Presence MUST be enforced!');
        assert.isFalse(authData.flags.at, 'For GetAssertion, Attestation Data flag must NOT be set!');
        assert.isFalse(authData.flags.ed, 'For GetAssertion, with no Extensions requested, Extensions Data flag MUST not be set!');

        return window.navigator.fido.webauthn.hash('SHA-256', stringToArrayBuffer(window.location.hostname))
            .then((rpIdHashCalculated) => {
                assert.strictEqual(hex.encode(rpIdHashCalculated), hex.encode(authData.rpIdHash), 'AuthData does not contain expected rpIdHash!');
            })
    })

    it(`P-2

        Send two valid GetAssertion request, and wait for both of them to succeed. Decode "authenticatorData" for each of responses, and check that Response1.counter is bigger than Response2.counter

    `, () => {
        let publicKey = generateGoodWebAuthnGetAssertion(credId);
        return navigator.credentials.get({ publicKey })
            .then((GetAssertionResp2) => {
                let counter1 = parseAuthData(GetAssertionResp.response.authenticatorData).counter
                let counter2 = parseAuthData(GetAssertionResp2.response.authenticatorData).counter
                assert.isAbove(counter2, counter1, 'The counter have not increased!');
            })
    })

    it(`P-3

        Hash clientDataJSON to create ClientDataHash. Concatenate authenticatorData and clientData to create signatureBase. Verify signature using signatureBase and previously obtained public key

    `, () => {

        return window.navigator.fido.webauthn.hash('SHA-256', GetAssertionResp.response.clientDataJSON)
            .then((ClientDataHash) => {
                let signatureBase = mergeArrayBuffers(GetAssertionResp.response.authenticatorData, ClientDataHash);

                return window.navigator.fido.webauthn.verifySignatureCOSE(cosePublicKey, signatureBase, GetAssertionResp.response.signature)
            })
            .then((signatureIsValid) => {
                assert.isTrue(signatureIsValid, 'Cannot validate the signature!');
            })
    })
})