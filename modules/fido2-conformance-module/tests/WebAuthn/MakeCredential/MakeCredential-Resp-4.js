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

        WebAuthn-Platform-MakeCred-Resp-4

        Test "android-safetynet" attestation

    `, function() {

    let attestationObject       = undefined;
    let attestationObjectStruct = undefined;
    let clientDataHash          = undefined;
    let metadata                = undefined;
    let nonceBuffer             = undefined;
    let startTimestamp          = undefined;
    let attStmt                 = undefined;
    let attStmtStruct           = undefined;

    before(function() {
        this.timeout(120000);

        let publicKey = generateGoodWebAuthnMakeCredential();
        publicKey.attestation = 'direct';
        metadata = getMetadataStatement();
        startTimestamp = new Date().getTime();
        return navigator.credentials.create({ publicKey })
            .then((response) => Promise.all([window.navigator.fido.webauthn.decodeToJSON(response.response.attestationObject),
                                             window.navigator.fido.webauthn.decodeToObjectStruct(response.response.attestationObject),
                                             window.navigator.fido.webauthn.hash('SHA-256', response.response.clientDataJSON)]))
            .then((response) => {
                attestationObject       = response[0];
                attestationObjectStruct = response[1];
                clientDataHash          = response[2];
                attStmt                 = attestationObject.attStmt;
                attStmtStruct           = attestationObjectStruct.attStmt;

                if(attestationObject.fmt !== 'android-safetynet') {
                    this.skip();
                }

                return window.navigator.fido.webauthn.hash('SHA-256', mergeArrayBuffers(attestationObjectStruct.authData, clientDataHash))
            })
            .then((response) => {
                nonceBuffer = response;
            })
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Decode "attStmt" CBOR MAP and: 
            (a) Check that "ver" field is of type TEXT
            (b) Check that "response" field is of type BYTE ARRAY
            (c) Decode "response" field to STRING
            (d) Verify that decoded string is a concatenation of three base64url encoded strings(header, payload and signature), separated by full stops
            (e) Split decoded string with fullstops
            (f) Decode header from base64url to UTF-8 string and successfully JSON parse it
            (g) Check that header contains "alg" field that is set to the algorithm corresponding to metadata statement
            (h) Check that header contains "x5c" field is set to a SEQUENCE of base64 encode X509 certificates
            (i) Check that metadata statement contains "attestationRootCertificates" field, and it’s not empty. 
            (j) Check that metadata statement "attestationTypes" SEQUENCE contains ATTESTATION_BASIC_FULL(0x3E07) 
            (k) For each attRootCert in "attestationRootCertificates" of the metadata statement:
                (1) Append attRootCert to the end of x5c SEQUENCE  and validate certificate sequence using the "Certification Path Validation" algorithm in section 6 of the [rfc5280]
                (2) If any chain was successfully validated, stop iteration, and proceed to the next step
                (3) If no chain was successfully validated, return an error
            (l) Check that attestation certificate is issued for attest.android.com
            (m) Decode payload from base64url to UTF-8 string and successfully JSON parse it
            (n) Hash clientData with SHA256 and get clientDataHash
            (o) Check that "nonce" is set to base64 encoded SHA256 hash of the concatenation of authData and clientDataHash.
            (p) Check that "ctsProfileMatch" is of type BOOLEAN and is set to true
            (q) Check that "timestampMs" is of type NUMBER

    `, () => {
        assert.isDefined(attStmt.ver, 'attStmt is missing "ver" field!');
        assert.isString(attStmt.ver, 'attStmt.ver MUST be of type String');

        assert.isDefined(attStmt.response, 'attStmt is missing "response" field!');
        assert.strictEqual(type(attStmtStruct.response), 'Uint8Array', 'attStmt.sig MUST be of type BYTE ARRAY!');

        let jwtString = arrayBufferToString(attStmtStruct.response);

        assert.match(jwtString, /^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/, 'JWT MUST be a concatenation of base64url encoded header, payload and signature, joined by full stop(.)');

        let jwtParts   = jwtString.split('.');

    /* ----- HEADER TESTS ----- */
        let headerJSON = B64URLToUTF8(jwtParts[0]);
        let header     = JSON.parse(headerJSON);

        assert.isDefined(header.x5c, 'Response.header missing x5c field!');

        assert.isDefined(metadata.attestationRootCertificates, 'Metadata does NOT contains mandatory attestationRootCertificates field!');
        assert.isArray(metadata.attestationRootCertificates, 'Metadata.attestationRootCertificates MUST be of type SEQUENCE!');
        assert.isNotEmpty(metadata.attestationRootCertificates, 'Metadata.attestationRootCertificates MUST NOT be empty!');

        assert.isDefined(metadata.attestationTypes, 'Metadata missing attestationTypes field!');
        assert.isArray(metadata.attestationTypes, 'Metadata.attestationTypes MUST be of type SEQUENCE!');
        assert.include(metadata.attestationTypes, ATTESTATION_TYPES.ATTESTATION_BASIC_FULL, 'Metadata.attestationTypes MUST include ATTESTATION_BASIC_FULL')

        let attStmtCertificateChain = header.x5c.map((cert) => base64StringCertToPEM(cert))
        let chainIsValid = false;
        for(let attestationRootCertificate of metadata.attestationRootCertificates) {
            let certPem = base64StringCertToPEM(attestationRootCertificate)
            let validationChain = attStmtCertificateChain.concat([certPem]);
            chainIsValid = chainIsValid || verifyCertificateChain(validationChain)                
        }
        assert.isTrue(chainIsValid, 'Can not validate certificate chain!');

        var ASN1Cert = ASN1.decode(header.x5c[0]);
        var CommonNameASN1 = ASN1.findOIDStructure(ASN1Cert.sub[0].sub[5], '2.5.4.3');

        assert.isDefined(CommonNameASN1, 'Certificate subject missing common name!');

        var CommonNameJSON = ASN1.structureToJSON(CommonNameASN1);
        var CommonName = CommonNameJSON.data[1].data

        assert.strictEqual(CommonName, 'attest.android.com', 'Expected attestation certificate to be issued for attest.android.com!');
   
    /* ----- BODY TESTS ----- */
        let bodyJSON = B64URLToUTF8(jwtParts[1]);
        let body     = JSON.parse(bodyJSON);

        assert.isDefined(body.nonce, 'Body is missing nonce field!');
        assert.strictEqual(body.nonce, base64.encode(nonceBuffer), 'Expected body.nonce to be set to base64 encoded SHA256 hash of the concatenation of authData and clientDataHash!');

        assert.isDefined(body.ctsProfileMatch, 'Body is missing ctsProfileMatch field!');
        assert.isBoolean(body.ctsProfileMatch, 'Body.ctsProfileMatch MUST be of type BOOLEAN!');
        assert.isTrue(body.ctsProfileMatch, 'Body.ctsProfileMatch MUST be true!');

        assert.isDefined(body.timestampMs, 'Body is missing timestampMs field!');
        assert.isNumber(body.timestampMs, 'Body.timestampMs MUST be of type NUMBER!');
    })

    it(`P-2

        Concatenate base64url encode header and payload using full stop to create signatureBase, and verify it signature using leaf certificate in header.x5c

    `, function() {
        assert.isDefined(attStmt.ver, 'attStmt is missing "ver" field!');
        assert.isString(attStmt.ver, 'attStmt.ver MUST be of type String');

        assert.isDefined(attStmt.response, 'attStmt is missing "response" field!');
        assert.strictEqual(type(attStmtStruct.response), 'Uint8Array', 'attStmt.sig MUST be of type BYTE ARRAY!');

        let jwtString = arrayBufferToString(attStmtStruct.response);
        let jwtParts  = jwtString.split('.');

        let headerJSON = B64URLToUTF8(jwtParts[0]);
        let header     = JSON.parse(headerJSON);

        let msg = hex.encode(stringToArrayBuffer(`${jwtParts[0]}.${jwtParts[1]}`));
        let key = base64StringCertToPEM(header.x5c[0]);
        let sig = hex.encode(base64url.decode(jwtParts[2]));

        return window.navigator.fido.webauthn.verifySignature('', key, sig, msg)
            .then((signatureIsValid) => {
                assert.isTrue(signatureIsValid, 'Cannot validate the signature!');
            })
    })
})
