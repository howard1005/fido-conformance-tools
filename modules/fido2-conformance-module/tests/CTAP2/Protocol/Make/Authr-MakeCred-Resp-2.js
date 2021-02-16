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

        Authr-MakeCred-Resp-2

        Test "packed" attestation

    `, function() {

    let makeCredResponses  = undefined
    let metadata           = window.config.test.metadataStatement;
    let rpId               = generateRandomDomain();
    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return getMakeCredentialResponseForAllAlgorithms(rpId)
            .then((responses) => {
                for(let response of responses) {
                    response.attStmt            = response.cborResponse[MakeCredRespKeys.attStmt];
                    response.attStmtStruct      = response.cborResponseStruct[MakeCredRespKeys.attStmt];

                    response.authDataStruct     = parseAuthData(response.cborResponseStruct[MakeCredRespKeys.authData]);
                    response.cosePublicKey      = tryDecodeCBORtoJSON(response.authDataStruct.COSEPublicKey)[0];
                    response.cosePublicKeyBuff  = response.authDataStruct.COSEPublicKey;

                    if(response.cborResponse[MakeCredRespKeys.fmt] !== 'packed') {
                        this.skip()
                        return
                    }
                }

                makeCredResponses = responses;
            })
    })

    after(function() {
        this.timeout(30000);
        return sendReset()
    })

    this.timeout(30000);
    // this.retries(3);
    
    let MakeCredRespKeys = {
        'fmt'      : 0x01,
        'authData' : 0x02,
        'attStmt'  : 0x03
    }

/* ----- POSITIVE TESTS ----- */

    it(`P-1

        Decode "attStmt" CBOR MAP and: 
            (a) check that "alg" field is presented it matches "alg" in PK
            (b) check that "sig" field is presented and it is of type BYTE STRING

    `, () => {
        for (let response of makeCredResponses) {
            assert.isDefined(response.attStmt.alg, 'attStmt is missing "alg" field!');
            assert.isNumber(response.attStmt.alg, 'attStmt.alg MUST be of type NUMBER');
            assert.isDefined(response.attStmt.alg, response.cosePublicKey[COSE_KEYS.alg], 'attStmt.alg DOES NOT match authrData.publicKey.alg');
            assert.isDefined(response.attStmt.sig, 'attStmt is missing "sig" field!');
            assert.strictEqual(type(response.attStmtStruct.sig), 'Uint8Array', 'attStmt.sig MUST be of type BYTE ARRAY!');
        }
    })

    it(`P-2

        If "x5c" presented: 
            (a) Check that "ecdaaKeyId" is NOT presented 
            (b) Check that "x5c" is of type SEQUENCE 
            (c) Check that metadata statement contains "attestationRootCertificates" field, and it’s not empty. 
            (d) Check that metadata statement "attestationTypes" SEQUENCE contains ATTESTATION_BASIC_FULL(0x3E07) 
            (e) Decode certificate chain 
            (f) If certificate chain does not contain attestationRootCertificates, append them to the chain 
            (g) Verify certificate chain 
            (h) Pick a leaf certificate of the chain and check that: 
                (1) Version is of type INTEGER and is set to 3 
                (2) Subject-C - is of type UTF8String, and is set to ISO 3166 code specifying the country where the Authenticator vendor is incorporated (UTF8String) 
                (3) Subject-O - is of type UTF8String, and is set to the legal name of the Authenticator vendor 
                (4) Subject-OU - is of type UTF8String, and is set to literal string “Authenticator Attestation” 
                (5) Subject-CN - is of type UTF8String, and is not empty
                (6) Basic Constraints extension MUST have the CA component set to false. 
                (7) [TBD] If the related attestation root certificate is used for multiple authenticator models, the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical. 
                (8) Check that certificate is not expired, is current(notBefore is set to the past date), and is valid for at least 5 years [TBD]
            (i) Concatenate authenticatorData and signData to clientDataHash. Using key extracted from leaf certificate, signData verify signature in "sig" field.

    `, function() {
        for (let response of makeCredResponses) {
            if(response.attStmt.x5c) {
                assert.isUndefined(response.attStmt.ecdaaKeyId, 'attStmt contains both ECDAA and FULL attestations!');
                assert.isArray(response.attStmt.x5c, 'attStmt.x5c MUST be of type SEQUENCE!');

                assert.isDefined(metadata.attestationRootCertificates, 'MetadataStatement does NOT contains mandatory attestationRootCertificates field!');
                assert.isArray(metadata.attestationRootCertificates, 'MetadataStatement.attestationRootCertificates MUST be of type SEQUENCE!');
                assert.isNotEmpty(metadata.attestationRootCertificates, 'MetadataStatement.attestationRootCertificates MUST NOT be empty!');

                assert.isDefined(metadata.attestationTypes, 'MetadataStatement missing attestationTypes field!');
                assert.isArray(metadata.attestationTypes, 'MetadataStatement.attestationTypes MUST be of type SEQUENCE!');
                assert.include(metadata.attestationTypes, ATTESTATION_TYPES.ATTESTATION_BASIC_FULL, 'MetadataStatement.attestationTypes MUST include ATTESTATION_BASIC_FULL')
                
                let attStmtCertificateChain = response.attStmt.x5c.map((cert) => base64StringCertToPEM(HEXToBASE64(cert)))

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
                assert.isDefined(certInfo.C, 'Attestation Certificate missing C:countryName attribute!');
                assert.include(listOfCountryCodes, certInfo.C, `CountryName attribute contains unknown "${certInfo.C}" ISO alpha2 code!`);

                assert.isDefined(certInfo.O, 'Attestation Certificate missing O:Organization attribute!');
                assert.isNotEmpty(certInfo.O, 'Attestation Certificate OU attribute MUST be set to the legal name of the authenticator vendor!');
                assert.isDefined(certInfo.OU, 'Attestation Certificate missing OU:OrganizationalUnit attribute!');
                assert.strictEqual(certInfo.OU, 'Authenticator Attestation', 'Attestation Certificate OU attribute MUST be set to the literal string "Authenticator Attestation"!');

                assert.isDefined(certInfo.CN, 'Attestation Certificate missing CN:CommonName attribute!');
                assert.isNotEmpty(certInfo.CN, 'Attestation Certificate CN attribute MUST NOT be empty!');

                assert.isDefined(certInfo.basicConstraintsCA, 'Attestation Certificate missing basicConstraints extension!');
                assert.isFalse(certInfo.basicConstraintsCA, 'Attestation Certificate basicConstraints CA component MUST be set to false!');

                assert.isTrue(certInfo.notBefore.getTime() < new Date().getTime(), 'Attestation Certificate notBefore MUST NOT be set in the future!');
                assert.isTrue(certInfo.notAfter.getTime() > new Date().getTime(), 'Attestation Certificate is expired!');

                if(getDateIn5Years().getTime() > certInfo.notAfter.getTime())
                    alert('Your device certificate is set to expire in less than five years! This may lead to some negative consequeses for your users! We advice to have atteststation certificate life of at least five years!');

                let signatureData = mergeArrayBuffers(response.cborResponseStruct[MakeCredRespKeys.authData], response.clientDataHash);
                let signature     = response.attStmtStruct.sig;

                let signatureIsValid = window.navigator.fido.fido2.crypto.verifySignature(leafCert, signature, signatureData);

                assert.isTrue(signatureIsValid, 'Cannot validate the signature!');
            } else {
                this.skip()
                return
            }
        }
    })

    it(`P-3

        If "ecdaaKeyId" presented: 
            (a) Check that "x5c" is NOT presented 
            (b) Check that metadata statement attestationFormats contains ATTESTATION_ECDAA(0x3E09) 
            (c) Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId (see [FIDOEcdaaAlgorithm]).

    `, function() {
        for (let response of makeCredResponses) {
            if(response.attStmt.ecdaaKeyId) {
                assert.isUndefined(response.attStmt.ecdaaKeyId, 'ECDAA attStmt can NOT contain FULL attestation as well!');

                assert.isDefined(metadata.attestationTypes, 'MetadataStatement missing attestationTypes field!');
                assert.isArray(metadata.attestationTypes, 'MetadataStatement.attestationTypes MUST be of type SEQUENCE!');
                assert.include(metadata.attestationTypes, ATTESTATION_TYPES.ATTESTATION_ECDAA, 'MetadataStatement.attestationTypes MUST include ATTESTATION_ECDAA');

                let signatureData = mergeArrayBuffers(response.cborResponseStruct[MakeCredRespKeys.authData], response.clientDataHash);
                let signature     = response.attStmtStruct.sig;

                throw new Error('ECDAA attestation is NOT supported yet!');
                // TODO: Implement ECDAA verification
            } else {
                this.skip()
                return
            }
        }
    })

    it(`P-4

        If neither "x5c" nor "ecdaaKeyId" is present, then self attestation is presented, then: 
            (a) Check that metadata statement contains "attestationRootCertificates" field, and it’s an empty ARRAY. 
            (b) Check that metadata statement attestationFormats contains ATTESTATION_BASIC_SURROGATE(0x3E08) 
            (c) Concatenate authenticatorData and clientDataHash to signData. Using public key extracted from authenticatorData, signData verify signature in "sig" field.

    `, function() {
        for (let response of makeCredResponses) {
            if(!response.attStmt.x5c && !response.attStmt.ecdaaKeyId) {
                assert.isDefined(metadata.attestationRootCertificates, 'MetadataStatement does NOT contains mandatory attestationRootCertificates field!');
                assert.isArray(metadata.attestationRootCertificates, 'MetadataStatement.attestationRootCertificates MUST be of type SEQUENCE!');
                assert.isEmpty(metadata.attestationRootCertificates, 'For self-attestation, Metadata.attestationRootCertificates MUST be empty!');

                assert.isDefined(metadata.attestationTypes, 'MetadataStatement missing attestationTypes field!');
                assert.isArray(metadata.attestationTypes, 'MetadataStatement.attestationTypes MUST be of type SEQUENCE!');
                assert.include(metadata.attestationTypes, ATTESTATION_TYPES.ATTESTATION_BASIC_SURROGATE, 'MetadataStatement.attestationTypes MUST include ATTESTATION_BASIC_SURROGATE');

                let signatureData    = mergeArrayBuffers(response.cborResponseStruct[MakeCredRespKeys.authData], response.clientDataHash);
                let signature        = response.attStmtStruct.sig;

                let signatureIsValid = navigator.fido.fido2.crypto.verifySignatureCOSE(response.cosePublicKeyBuff, signatureData, signature)
                assert.isTrue(signatureIsValid, 'The assertion signature can not be verified!');
            } else {
                this.skip()
            }
        }
    })
})