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

        Client-Ext-Android-KeyStoreAttestation-1.js

        Test client processing Android Key Attestation Extention

    `, function() {

    before(function() {
        if(!window.config.test.metadataStatement.supportedExtensions) {
            this.skip();
        } else {
            let found = false;
            for(let ext of window.config.test.metadataStatement.supportedExtensions) {
                if(ext.id === 'fido.uaf.android.key_attestation')
                    found = true;
            }

            if(!found)
                this.skip();
        }
    })
        
    this.timeout(30000);
    this.retries(3);

    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    })

    let findASN1Tag = (sequence, tag) => {
        for(let item of sequence) {
            if(item.type === `[${tag}]`)
                return item.data[0]
        }
    }

    let isSilentAuthenticator = () => {
        for(let uvd of window.config.test.metadataStatement.userVerificationDetails) {
            for(let uv of uvd) {
               if(uv.userVerification === USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_NONE) {
                    return true
                } 
            }
        }

        return false
    }

    // https://source.android.com/security/keystore/tags#PURPOSE
    let Keystore_KeyPurpose = {
        ENCRYPT:    0,
        DECRYPT:    1,
        SIGN:       2,
        VERIFY:     3,
        DERIVE_KEY: 4,
        WRAP_KEY:   5
    }

    // https://source.android.com/security/keystore/tags#ORIGIN
    let Keystore_Origin = {
        KM_ORIGIN_GENERATED: 0,
        KM_ORIGIN_IMPORTED:  2,
        KM_ORIGIN_UNKNOWN:   3
    }

    // https://source.android.com/security/keystore/tags#USER_AUTH_TYPE
    let Keystore_HardwareAuthenticatorType = {
        NONE: 0,
        PASSWORD: 1,
        FINGERPRINT: 2,
        ANY: 0xffffffff,

        0: 'NONE',
        1: 'PASSWORD',
        2: 'FINGERPRINT',
        0xffffffff: 'ANY'
    }

    // https://source.android.com/security/keystore/tags#DIGEST
    let Keystore_Digest = {
        NONE: 0,
        MD5: 1,
        SHA1: 2,
        SHA_2_224: 3,
        SHA_2_256: 4,
        SHA_2_384: 5,
        SHA_2_512: 6
    };

    /**
     * Takes ASN1 tagged dirty hex e.g. (32 byte)\n6C4E760E4313...F08FF6FA0AB49
     * and returns base64url e.g. bE52DkMTahcX...GPKrnkvC8I_2-gq0k
     * @param  {[type]} asn1hex [description]
     * @return {[type]}         [description]
     */
    let ASN1DirtyHexToBase64url = (asn1hex) => {
        let cleanHex = asn1hex.replace(/^\(\d+\s\w+\)\n/, '');

        return base64url.encode(hex.decode(cleanHex))
    }

/* ---------- Positive Tests ---------- */
    it(`P-1

        Send a valid UAF Registration request for the given metadata statement, with a valid "fido.uaf.android.key_attestation" extension, wait for the response, check that API does NOT return an error, and: 
            (a) Validate certificate chain 
            (b) Identify and parse leaf certificate, and check that: 
                (1) KeyUsage is only set to SIGN and VERIFY 
                (2) Key Attestation extension (1.3.6.1.4.1.11129.2.1.17) is NOT missing. 
                (3) Check that Extension attestationChallenge is set to FCHash 
                (4) If KEY_PROTECTION_TEE bit is set in metadata.keyProtection, then test teeEnforced AuthorizationList, else if KEY_PROTECTION_SOFTWARE bit is set, use softwareEnforced AuthorizationList. 
                (5) Check that AuthorizationList.origin([702]) is set to KM_ORIGIN_GENERATED 
                (6) Check that AuthorizationList.purpose([1]) is set to KM_PURPOSE_SIGN 
                (7) Check that AuthorizationList.keySize([3]) is acceptable, i.e. = 2048 (bit) RSA or =256 (bit) ECDSA.
                (8) Check that AuthorizationList.digest([5]) is set to KM_DIGEST_SHA_2_256(0x04). 
                (9) Check that AuthorizationList.noAuthRequired([503]) is not present (unless the Metadata Statement marks this authenticator as silent authenticator, i.e. userVerificaton set to USER_VERIFY_NONE). 
                (10) Check that AuthorizationList.allApplications([600]) is not present, since FIDO Uauth keys must be bound to the generating app (AppID).

    `, () => {
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((data) => {
                data[0].header.exts = [
                    {
                        'id': 'fido.uaf.android.key_attestation',
                        'data': '',
                        'fail_if_unknown': false
                    }
                ]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }
                return authenticator.processUAFOperation(uafmessage)
            })
            .then((response) => {
                let message = tryDecodeJSON(response.uafProtocolMessage)[0];
                let extensionResponse = message.assertions[0].exts;
                let assertion = message.assertions[0].assertion;

                assert.isDefined(extensionResponse, 'RegistrationAssertion missing exts key!');
                assert.isNotEmpty(extensionResponse, 'RegistrationAssertion.exts MUST not be empty!');

                let foundExt = undefined;
                for(let ext of extensionResponse) {
                    if(ext.id === 'fido.uaf.android.key_attestation')
                        foundExt = ext;
                }

                assert.isDefined(foundExt, 'RegistrationAssertion.exts missing "fido.uaf.android.key_attestation" extension!');

                let certificateChain = tryDecodeJSON(foundExt.data);
                assert.isArray(certificateChain, 'CertificateChain MUST be of type SEQUENCE!');

                let goodChain = [];
                for(let cert of certificateChain) {
                    assert.isTrue(isValidBase64String(cert), 'The certificate in the certificateChain contains non-base64 characters. Most likely new-line characters. Please remove all non-base64 characters and try again.')

                    cert = base64StringCertToPEM(cert);

                    goodChain.push(cert)
                }

                assert.isTrue(verifyCertificateChain(goodChain), 'CertificateChain can NOT be validated!');

                let leafCert = certificateChain[0];
                let ASN1Cert = ASN1.decode(leafCert);

                let keyAttestationExtension = ASN1.findOIDStructure(ASN1Cert, '1.3.6.1.4.1.11129.2.1.17');
                assert.isDefined(keyAttestationExtension, 'Certificate missing X509 KeyAttestationExtension!');

                let keyAttestationExtensionJSON = ASN1.structureToJSON(keyAttestationExtension);
                assert.isTrue(keyAttestationExtensionJSON.type === "SEQUENCE", "Extention MUST be of type SEQUENCE!");
                assert.isTrue(keyAttestationExtensionJSON.data.length === 2, "Extention SEQUENCE contain exactly two members!");
                
                let extensionData;
                if(keyAttestationExtensionJSON.data[0].type !== "OBJECT_IDENTIFIER") {
                    extensionData = keyAttestationExtensionJSON.data[0].data[0].data;
                } else {
                    extensionData = keyAttestationExtensionJSON.data[1].data[0].data;
                }    

                let TLVBUFFER = base64url.decode(assertion);
                let TLVSTRUCT = tlv.parser.parse(TLVBUFFER);
                assert.strictEqual(ASN1DirtyHexToBase64url(extensionData[4].data), TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_FINAL_CHALLENGE_HASH, 'attestationChallenge MUST be set to base64url encoded FinalChallengeHash!');

                let softwareEnforced = extensionData[6].data;
                let teeEnforced      = extensionData[7].data;
                if(!(!!(window.config.test.metadataStatement.keyProtection & KEY_PROTECTION_TYPES_TO_INT.KEY_PROTECTION_TEE) || !!(window.config.test.metadataStatement.keyProtection & KEY_PROTECTION_TYPES_TO_INT.KEY_PROTECTION_SOFTWARE))) {
                    throw new Error('In metadataStatement.keyProtection neither KEY_PROTECTION_TEE nor KEY_PROTECTION_SOFTWARE are set!');
                }

                let attestationApplicationId = findASN1Tag(softwareEnforced, 709);
                assert.isDefined(attestationApplicationId, 'attestationApplicationId key is missing!');
                let packageName = attestationApplicationId.data[0].data[0].data[0].data[0].data;
                assert.isTrue(packageName === window.config.test.packageName || packageName === window.config.test.ASMPackageName, 'packageName name in keyAttestationExtension does not match packageName of the tested application.')

                let origin = findASN1Tag(teeEnforced, 702);
                assert.isDefined(origin, 'origin key is missing!')
                assert.strictEqual(origin.type, 'INTEGER', 'origin MUST be of type INTEGER!');
                assert.strictEqual(parseInt(origin.data), Keystore_Origin.KM_ORIGIN_GENERATED, `origin MUST be set to ${Keystore_Origin.KM_ORIGIN_GENERATED}. Given ${origin.data}`);

                let keySize = findASN1Tag(teeEnforced, 3);
                assert.isDefined(keySize, 'keySize key is missing!')
                assert.strictEqual(keySize.type, 'INTEGER', 'keySize MUST be of type INTEGER!');
                if(ALG_DIR[window.config.test.metadataStatement.authenticationAlgorithm].indexOf('RSA') !== -1)
                    assert.strictEqual(parseInt(keySize.data), 2048, `keySize MUST be set to ${2048}. Given ${keySize.data}`);
                else
                    assert.strictEqual(parseInt(keySize.data), 256, `keySize MUST be set to ${256}. Given ${keySize.data}`);
                
                let digest = findASN1Tag(teeEnforced, 5).data[0];
                assert.isDefined(digest, 'digest key is missing!')
                assert.strictEqual(digest.type, 'INTEGER', 'digest MUST be of type INTEGER!');
                assert.strictEqual(parseInt(digest.data), Keystore_Digest.SHA_2_256, `digest MUST be set to ${Keystore_Digest.SHA_2_256}. Given ${digest.data}`);

                let noAuthRequired = findASN1Tag(teeEnforced, 503);
                if(isSilentAuthenticator()) {
                    assert.isDefined(noAuthRequired, 'For silent authenticators, "noAuthRequired" MUST be presented!')

                } else {
                    assert.isUndefined(noAuthRequired, 'For NON-silent authenticators, "noAuthRequired" key MUST be missing!')
                }

                let allApplications = findASN1Tag(teeEnforced, 600);
                assert.isUndefined(allApplications, 'allApplications MUST not be presented!');                
            })
    })
})
