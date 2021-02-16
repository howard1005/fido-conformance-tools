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

        WebAuthn-Platform-MakeCred-Resp-3

        Test "tpm" attestation

    `, function() {

    let attestationObject       = undefined;
    let attestationObjectStruct = undefined;
    let clientDataHash          = undefined;
    let metadata                = undefined;
    let authDataStruct          = undefined;
    let cosePublicKeyStruct     = undefined;
    let attStmt                 = undefined;
    let attStmtStruct           = undefined;
    before(function() {
        this.timeout(120000);

        let publicKey = generateGoodWebAuthnMakeCredential();
        publicKey.attestation = 'direct';
        metadata = getMetadataStatement();

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

                authDataStruct          = parseAuthData(attestationObjectStruct.authData);
                return window.navigator.fido.webauthn.decodeToObjectStruct(authDataStruct.COSEPublicKey);
            })
            .then((response) => {
                cosePublicKeyStruct = response;

                if(attestationObject.fmt !== 'tpm')
                    this.skip();
            })
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Decode "attStmt" CBOR MAP and: 
            (a) check that "alg" field is presented it matches "alg" in Public Key
            (b) check that "sig" field is presented and it is of type BYTE STRING
            (c) check that "ver" is set to "2.0"
            (d) decode "certInfo" TPMS_ATTEST structure and check that:
                (1) Verify that "magic" is set to TPM_GENERATED_VALUE.
                (2) Verify that "type" is set to TPM_ST_ATTEST_CERTIFY.
                (3) Verify that "extraData" is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
                (4) Verify that "attested" contains a  p structure as specified in [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
            (e) check that pubArea.unique is set to then raw public key. For RSA its a 2048 bit modulus n

    `, () => {
        assert.isDefined(attStmt.alg, 'attStmt is missing "alg" field!');
        assert.isNumber(attStmt.alg, 'attStmt.alg MUST be of type NUMBER');

        assert.isDefined(attStmt.sig, 'attStmt is missing "sig" field!');
        assert.strictEqual(type(attStmtStruct.sig), 'Uint8Array', 'attStmt.sig MUST be of type BYTE ARRAY!');

        assert.strictEqual(attStmt.ver, '2.0', 'The "ver" field MUST be set to "2.0"!');

        let pubArea  = parseTPMT_PUBLIC(attStmtStruct.pubArea);
        assert.strictEqual(hex.encode(pubArea.unique), hex.encode(cosePublicKeyStruct[COSE_KEYS.n]), 'TPMT_PUBLIC.unique MUST be set to the raw public key!');

        let certInfo = parseTPMS_ATTEST(attStmtStruct.certInfo);
        assert.strictEqual(certInfo.magic, TPM_GENERATED_VALUE, 'The "magic" is not set to TPM_GENERATED_VALUE(0xff544347)!');
        assert.isDefined(certInfo.type, 'The "type" is set to a value that is not a member of TPM_ST!');

        let nameAlgHex = hex.encode(new Uint8Array([0x00, TPM_ALG_ID[pubArea.nameAlg]]));

        let hashAlg    = undefined;
        if(pubArea.nameAlg === 'TPM_ALG_SHA256')
            hashAlg = 'SHA-256';
        else
            hashAlg = 'SHA-1';

        return window.navigator.fido.webauthn.hash(hashAlg, attStmtStruct.pubArea)
            .then((HnameAlg) => {
                let nameHex = nameAlgHex + hex.encode(HnameAlg);

                assert.strictEqual(hex.encode(certInfo.attested.name), nameHex, 'Could not verify the validity of the TPMS_CERTIFY_INFO.name in attested field!');

                let attToBeSigned = mergeArrayBuffers(attestationObjectStruct.authData, clientDataHash);
                let hashFunction  = COSE_ALG_HASH[attStmt.alg];

                return window.navigator.fido.webauthn.hash(hashFunction, attToBeSigned)
            })
            .then((attToBeSignedHash) => {
                assert.strictEqual(hex.encode(certInfo.extraData), hex.encode(attToBeSignedHash), `The "extraData" is not set to the hash(${hashFunction}) of the attToBeSigned!`);
            })
    })

    it(`P-2

        If "x5c" presented: 
            (a) Check that "ecdaaKeyId" is NOT presented 
            (b) Check that "x5c" is of type SEQUENCE 
            (c) Check that metadata statement contains "attestationRootCertificates" field, and it’s not empty. 
            (d) Check that metadata statement "attestationTypes" SEQUENCE contains ATTESTATION_ATTCA(0x3E0A) 
            (e) Decode certificate chain 
            (f) For each certificate in Metadata.attestationRootCertificates, try appending it to the authenticator certificate chain and verifying the chain it self, until one chain will succeed.
            (h) Pick a leaf AIK certificate of the chain and check that: 
                (1) Version is of type INTEGER and is set to 3 
                (2) Check that Subject SEQUENCE is empty
                (3) Verify Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
                (4) The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
                (5) Basic Constraints extension MUST have the CA component set to false. 
            (i) Verify signature over certInfo using key extracted from leaf certificate.

    `, function() {
        if(attStmt.x5c) {
            let attStmt = attestationObject.attStmt;
            let attStmtStruct = attestationObjectStruct.attStmt;

            assert.isUndefined(attStmt.ecdaaKeyId, 'attStmt contains both ECDAA and FULL attestations!');
            assert.isArray(attStmt.x5c, 'attStmt.x5c MUST be of type SEQUENCE!');

            assert.isDefined(metadata.attestationRootCertificates, 'MetadataStatement does NOT contains mandatory attestationRootCertificates field!');
            assert.isArray(metadata.attestationRootCertificates, 'MetadataStatement.attestationRootCertificates MUST be of type SEQUENCE!');
            assert.isNotEmpty(metadata.attestationRootCertificates, 'MetadataStatement.attestationRootCertificates MUST NOT be empty!');

            assert.isDefined(metadata.attestationTypes, 'MetadataStatement missing attestationTypes field!');
            assert.isArray(metadata.attestationTypes, 'MetadataStatement.attestationTypes MUST be of type SEQUENCE!');
            assert.include(metadata.attestationTypes, ATTESTATION_TYPES.ATTESTATION_ATTCA, 'MetadataStatement.attestationTypes MUST include ATTESTATION_ATTCA')
        
            let attStmtCertificateChain = attStmt.x5c.map((cert) => base64StringCertToPEM(HEXToBASE64(cert)))

            let chainIsValid = false;
            for(let attestationRootCertificate of metadata.attestationRootCertificates) {
                let certPem = base64StringCertToPEM(attestationRootCertificate)
                let validationChain = attStmtCertificateChain.concat([certPem]);
                chainIsValid = chainIsValid || verifyCertificateChain(validationChain)                
            }

            assert.isTrue(chainIsValid, 'Can not validate certificate chain!');

            let leafCert = attStmtCertificateChain[0];

            let certificate = new jsrsasign.X509();
            certificate.readCertPEM(leafCert);

            let certInfo = getCertificateInfoObject(certificate);

            assert.strictEqual(certInfo.version, 3, 'Attestation Certificate version MUST be v3!');

            assert.isDefined(certInfo.basicConstraintsCA, 'Attestation Certificate missing basicConstraints extension!');
            assert.isFalse(certInfo.basicConstraintsCA, 'Attestation Certificate basicConstraints CA component MUST be set to false!');

            assert.isTrue(certInfo.notBefore.getTime() < new Date().getTime(), 'Attestation Certificate notBefore MUST NOT be set in the future!');
            assert.isTrue(certInfo.notAfter.getTime() > new Date().getTime(), 'Attestation Certificate is expired!');

            let ASN1Cert = ASN1.decode(HEXToBASE64(attStmt.x5c[0]));

            let ExtendedKeyUsageExtension = ASN1.findOIDStructure(ASN1Cert, '2.23.133.8.3');
            assert.isDefined(ExtendedKeyUsageExtension, 'Certificate missing X509 Extended Key Usage extension!');

            let sigparams = getFIDOAlgorithmParams({3: attStmt.alg})
            // TODO: Discuss with ADAM
            // if(getDateIn5Years().getTime() > certInfo.notAfter.getTime())
                // alert('Your device certificate is set to expire in less than 5 years! This may lead to some negative consequeses for your user!');

            return window.navigator.fido.webauthn.verifySignature(sigparams.signingScheme, leafCert, attStmt.sig, attStmt.certInfo)
                .then((signatureIsValid) => {
                    assert.isTrue(signatureIsValid, 'Cannot validate the signature!');
                })
        } else {
            this.skip()
        }
    })

    it(`P-3

        If "ecdaaKeyId" presented: 
            (a) Check that "x5c" is NOT presented 
            (b) Check that metadata statement attestationFormats contains ATTESTATION_ECDAA(0x3E09) 
            (c) Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId (see [FIDOEcdaaAlgorithm]).

    `, function() {
        if(attStmt.ecdaaKeyId) {
            assert.isUndefined(attStmt.x5c, 'ECDAA attStmt can NOT contain FULL attestation as well!');

            assert.isDefined(metadata.attestationTypes, 'MetadataStatement missing attestationTypes field!');
            assert.isArray(metadata.attestationTypes, 'MetadataStatement.attestationTypes MUST be of type SEQUENCE!');
            assert.include(metadata.attestationTypes, ATTESTATION_TYPES.ATTESTATION_ECDAA, 'MetadataStatement.attestationTypes MUST include ATTESTATION_ECDAA');

            let signatureData = mergeArrayBuffers(hex.decode(cborResponse[MakeCredRespKeys.authData]), clientDataHash);
            let signature     = hex.decode(attStmt.sig);

            throw new Error('ECDAA attestation is NOT supported yet!');
            // TODO: Implement ECDAA verification
        } else {
            this.skip()
        }
    })
})
