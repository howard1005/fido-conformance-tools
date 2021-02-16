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

        Metadata-Stmt-1

        Verify compliance of Metadata statement fields.

    `, function() {

    let Metadata = window.config.test.metadataStatement;

/* ---------- Positive Tests ---------- */
    it(`P-1

        If Metadata contains "legalHeader", it MUST be of type DOMString, and MUST not be empty

    `, function() {
        if(Metadata.legalHeader) {
            assert.isString(Metadata.legalHeader, 'Metadata.legalHeader MUST be of type DOMString!');
            assert.isNotEmpty(Metadata.legalHeader, 'Metadata.legalHeader can not be empty!');
        } else {
            this.skip()
        }
    })

    it(`P-2

        Required "attestationCertificateKeyIdentifiers", of type SEQUENCE, not empty, and it MUST contain at least one lowercase HEX encoded 20byte SHA-1 of the tbsCertificate.

    `, () => {
        assert.isDefined(Metadata.attestationCertificateKeyIdentifiers, 'Metadata is missing "attestationCertificateKeyIdentifiers" field!');
        assert.isArray(Metadata.attestationCertificateKeyIdentifiers, 'Metadata.attestationCertificateKeyIdentifiers is NOT of type SEQUENCE!');
        assert.isNotEmpty(Metadata.attestationCertificateKeyIdentifiers, 'Metadata.attestationCertificateKeyIdentifiers can NOT be empty!');

        for(let keyId of Metadata.attestationCertificateKeyIdentifiers) {
            assert.strictEqual(keyId.length, 40, 'Metadata.attestationCertificateKeyIdentifiers contains keyID that is not 20 bytes long!');
            assert.match(keyId, /^[a-f0-9]{40}$/, 'Metadata.attestationCertificateKeyIdentifiers contains keyID that is not lowercase hex encoded!');
        }
    })

    it(`P-3

        Required "aaid" and "aaguid" fields to be undefined!

    `, () => {
        assert.isUndefined(Metadata.aaid, 'Metadata.aaid MUST be undefined!');
        assert.isUndefined(Metadata.aaguid, 'Metadata.aaguid MUST be undefined!');
    })

    it(`P-4

        Required "description", of type DOMString.

    `, () => {
        assert.isDefined(Metadata.description, 'Metadata is missing description field!');
        assert.isString(Metadata.description, 'description field is not a DOMString!');
        assert.isTrue(Metadata.description.length > 0, 'description cannot be empty!');
    })


    it(`P-5

        If Metadata contain "alternativeDescriptions" field, then:
            (a) Check that its of type Dictionary
            (b) Check that each of the keys is correctly formated IETF language code(ru, fr-FR)
            (c) Check that values are of type DOMString, and are not empty
            (d) Check that it's max length of 200 characters

    `, function() {
        if(Metadata.alternativeDescriptions) {
            assert.isObject(Metadata.alternativeDescriptions, 'Metadata.alternativeDescriptions is NOT of type Dictionary!');
            for(let key in Metadata.alternativeDescriptions) {
                assert.match(key, /^[a-z]{2}(-[A-Z]{2})?$/, `The key ${key} is not in IETF format!`)
                assert.isString(Metadata.alternativeDescriptions[key], `The value for "${key}" is not of type DOMString!`);
                assert.isNotEmpty(Metadata.alternativeDescriptions[key], `The value for the key "${key}" is empty!`);
                assert.isBelow(Metadata.alternativeDescriptions[key].length, 200, `The value for "${key}" is longer than 200 characters!`);
            }
        } else {
            this.skip()
        }
    })

    it(`P-6

        Required "authenticatorVersion", of type unsigned short.

    `, () => {
        assert.isNumber(Metadata.authenticatorVersion, 'authenticatorVersion MUST be a number!');
    })

    it(`P-7

        If "protocolFamily" field is presented, it must be of type DOMString, and equal to "u2f".

    `, () => {
        assert.isDefined(Metadata.protocolFamily, 'Metadata is missing "protocolFamily" field!');
        assert.isString(Metadata.protocolFamily, 'protocolFamily field MUST be of type DOMString!');
        assert.isNotEmpty(Metadata.protocolFamily, 'protocolFamily MUST not be empty!');
        assert.strictEqual(Metadata.protocolFamily, 'u2f', 'protocolFamily MUST be set to "u2f"');
    })

    it(`P-8

        Required "upv", of type Version[].
            MUST not be empty.
            MUST contain { "major": 1, "minor": 1 }.

    `, () => {
        assert.isDefined(Metadata.upv, 'Metadata is missing "upv" field');
        assert.isArray(Metadata.upv, 'Metadata.upv MUST be of type Dictionary!');
        assert.isNotEmpty(Metadata.upv, 'Metadata.upv cannot be empty!');
        assert.deepInclude(Metadata.upv, { 'major': 1, 'minor': 1 }, 'Metadata.upv does not contain { "major": 1, "minor": 1 }!');
    })

    it(`P-9

        Required "assertionScheme", of type DOMString.
            MUST be "U2FV1BIN".

    `, () => {
        assert.isDefined(Metadata.assertionScheme, 'Metadata is missing assertionScheme field!');
        assert.isString(Metadata.assertionScheme, 'Metadata.assertionScheme MUST be of type DOMString!');
        assert.strictEqual(Metadata.assertionScheme, 'U2FV1BIN', 'Metadata.assertionScheme MUST be set to "U2FV1BIN"!');
    })

    it(`P-10

        Required Metadata to contain "authenticationAlgorithm" field, that is of type Number, is not zero, and set to ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW(0x0002)

    `, () => {
        assert.isDefined(Metadata.authenticationAlgorithm, 'Metadata missing authenticationAlgorithm field!');
        assert.isNumber(Metadata.authenticationAlgorithm, `Metadata.authenticationAlgorithm is not of type Number`);
        assert.strictEqual(ALG_DIR_TO_INT.ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW, Metadata.authenticationAlgorithm, `Metadata.authenticationAlgorithm MUST be set to ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW(0x0001)`);
    })

    it(`P-11

        For U2F, "authenticationAlgorithms" MUST be undefined

    `, function() {
        assert.isUndefined(Metadata.authenticationAlgorithms, 'For U2F, publicKeyAlgAndEncodings MUST be undefined!');
    })

    it(`P-12

        Required Metadata to contain "publicKeyAlgAndEncoding" field, that is of type Number, is not zero, and is set to ALG_KEY_ECC_X962_RAW(0x0100)

    `, () => {
        assert.isDefined(Metadata.publicKeyAlgAndEncoding, 'Metadata missing publicKeyAlgAndEncoding field!');
        assert.isNumber(Metadata.publicKeyAlgAndEncoding, `Metadata.publicKeyAlgAndEncoding is not of type Number`);
        assert.strictEqual(ALG_DIR_TO_INT.ALG_KEY_ECC_X962_RAW, Metadata.publicKeyAlgAndEncoding, `Metadata.publicKeyAlgAndEncoding MUST be set to ALG_KEY_ECC_X962_RAW(0x0100)`);
    })

    it(`P-13

        For U2F, "publicKeyAlgAndEncodings" MUST be undefined

    `, function() {
        assert.isUndefined(Metadata.publicKeyAlgAndEncodings, 'For U2F, publicKeyAlgAndEncodings MUST be undefined!');
    })

    it(`P-14

        Required Metadata to contain "attestationTypes" field, of type SEQUENCE. It MUST NOT be empty.

        Each member MUST be of type Number, and MUST be a valid ATTESTATION constants in FIDO Registry.

    `, () => {
        assert.isDefined(Metadata.attestationTypes, 'Metadata is missing "attestationTypes" field!');
        assert.isArray(Metadata.attestationTypes, 'Metadata.attestationTypes MUST be of type SEQUENCE!');
        assert.isNotEmpty(Metadata.attestationTypes, 'Metadata.attestationTypes MUST not be empty!');

        for(let key of Metadata.attestationTypes) {
            assert.isNumber(key, `Key "${key}" is not of type Number`);
            assert.isDefined(ATTESTATION_TYPES[key], `The key "${key}" is not a valid attestation type!`);
        }
    })

    it(`P-15

        Required Metadata to contain "userVerificationDetails" field, of type SEQUENCE. It MUST NOT be empty.

        For each VerificationMethodDescriptor in the two dimension SEQUENCE check that:
            (a) "userVerification" field is NOT missing, and its value is set to a single USER_VERIFY constant in FIDO Registry
            (b) If "caDesc" is presented:
                (1) Check that "userVerification" field is set to USER_VERIFY_PASSCODE.
                (2) Check that its of type Dictionary
                (3) Check that "caDesc" contains "base" field, and its of type Number, and is not 0 or less
                (4) Check that "caDesc" contains "minLength" field, and its of type Number, and is not 0 or less
                (5) If "caDesc" contains "maxRetries" field, and its of type Number, and is not 0 or less
                (6) If "caDesc" contains "blockSlowdown" field, and its of type Number, and is not 0 or less
            (c) If "baDesc" is presented:
                (1) Check that "userVerification" field is set to one of USER_VERIFY_FINGERPRINT, USER_VERIFY_VOICEPRINT, USER_VERIFY_FACEPRINT, USER_VERIFY_EYEPRINT, or USER_VERIFY_HANDPRINT.
                (2) Check that its of type Dictionary
                (3) If "baDesc" contains "FAR" field, and its of type Number, and is not 0 or less
                (4) If "baDesc" contains "FRR" field, and its of type Number, and is not 0 or less
                (5) If "baDesc" contains "EER" field, and its of type Number, and is not 0 or less
                (6) If "baDesc" contains "FAAR" field, and its of type Number, and is not 0 or less
                (7) If "baDesc" contains "maxReferenceDataSets" field, and its of type Number, and is not 0 or less
                (8) If "baDesc" contains "maxRetries" field, and its of type Number, and is not 0 or less
                (9) If "baDesc" contains "blockSlowdown" field, and its of type Number, and is not 0 or less
            (d) If "paDesc" is presented:
                (1) Check that "userVerification" field is set to USER_VERIFY_PATTERN.
                (2) Check that its of type Dictionary
                (3) Check that "paDesc" contains "minComplexity" field, and its of type Number, and is not 0 or less
                (4) If "paDesc" contains "maxRetries" field, and its of type Number, and is not 0 or less
                (5) If "paDesc" contains "blockSlowdown" field, and its of type Number, and is not 0 or less

    `, () => {
        assert.isDefined(Metadata.userVerificationDetails, 'Metadata is missing "userVerificationDetails" field!')
        assert.isArray(Metadata.userVerificationDetails, 'Metadata.userVerificationDetails MUST be of type SEQUENCE!');
        assert.isNotEmpty(Metadata.userVerificationDetails, 'Metadata.userVerificationDetails MUST not be empty!');

        for(let uvor of Metadata.userVerificationDetails) {
            assert.isArray(uvor, 'Metadata.userVerificationDetails member MUST be of type SEQUENCE!');

            for(let uvand of uvor) {
                assert.isObject(uvand, 'VerificationMethodDescriptor MUST be of type Dictionary')
                assert.isDefined(uvand.userVerification, 'VerificationMethodDescriptor is missing "userVerification" field!');
                assert.isDefined(USER_VERIFICATION_METHODS[uvand.userVerification], 'VerificationMethodDescriptor.userVerification is not a valid USER_VERIFY constant!');

                if(uvand.caDesc) {
                    assert.strictEqual(uvand.userVerification, USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_PASSCODE, 'If "VerificationMethodDescriptor" contains "caDesc", then "userVerification" MUST be set be set to USER_VERIFY_PASSCODE(0x00000004)');
                    assert.isObject(uvand.caDesc, 'CodeAccuracyDescriptor MUST be of type Dictionary!');

                    assert.isDefined(uvand.caDesc.base, 'CodeAccuracyDescriptor is missing "base" field!');
                    assert.isNumber(uvand.caDesc.base, 'CodeAccuracyDescriptor.base MUST be of type number!');
                    assert.isAbove(uvand.caDesc.base, 0, 'CodeAccuracyDescriptor.base MUST be bigger than 0!');

                    assert.isDefined(uvand.caDesc.minLength, 'CodeAccuracyDescriptor is missing "minLength" field!');
                    assert.isNumber(uvand.caDesc.minLength, 'CodeAccuracyDescriptor.minLength MUST be of type number!');
                    assert.isAbove(uvand.caDesc.minLength, 0, 'CodeAccuracyDescriptor.minLength MUST be bigger than 0!');

                    if(uvand.caDesc.maxRetries) {
                        assert.isNumber(uvand.caDesc.maxRetries, 'CodeAccuracyDescriptor.maxRetries MUST be of type number!');
                        assert.isAbove(uvand.caDesc.maxRetries, 0, 'CodeAccuracyDescriptor.maxRetries MUST be bigger than 0!');
                    }

                    if(uvand.caDesc.blockSlowdown) {
                        assert.isNumber(uvand.caDesc.blockSlowdown, 'CodeAccuracyDescriptor.blockSlowdown MUST be of type number!');
                        assert.isAbove(uvand.caDesc.blockSlowdown, 0, 'CodeAccuracyDescriptor.blockSlowdown MUST be bigger than 0!');
                    }
                }

                if(uvand.baDesc) {
                    assert.include(['USER_VERIFY_FINGERPRINT', 'USER_VERIFY_VOICEPRINT', 'USER_VERIFY_FACEPRINT', 'USER_VERIFY_EYEPRINT', 'USER_VERIFY_HANDPRINT'], USER_VERIFICATION_METHODS[uvand.userVerification], 'If "VerificationMethodDescriptor" contains "baDesc", then "userVerification" MUST be set be set to one of USER_VERIFY_FINGERPRINT(0x00000002), USER_VERIFY_VOICEPRINT(0x00000008), USER_VERIFY_FACEPRINT(0x00000010), USER_VERIFY_EYEPRINT(0x000000) or USER_VERIFY_HANDPRINT(0x00000100)!');
                    assert.isObject(uvand.baDesc, 'BiometricAccuracyDescriptor MUST be of type Dictionary!');

                    if(uvand.baDesc.FAR) {
                        assert.isNumber(uvand.baDesc.FAR, 'BiometricAccuracyDescriptor.FAR MUST be of type number!');
                        assert.isAbove(uvand.baDesc.FAR, 0, 'BiometricAccuracyDescriptor.FAR MUST be bigger than 0!');
                    }

                    if(uvand.baDesc.FRR) {
                        assert.isNumber(uvand.baDesc.FRR, 'BiometricAccuracyDescriptor.FRR MUST be of type number!');
                        assert.isAbove(uvand.baDesc.FRR, 0, 'BiometricAccuracyDescriptor.FRR MUST be bigger than 0!');
                    }

                    if(uvand.baDesc.EER) {
                        assert.isNumber(uvand.baDesc.EER, 'BiometricAccuracyDescriptor.EER MUST be of type number!');
                        assert.isAbove(uvand.baDesc.EER, 0, 'BiometricAccuracyDescriptor.EER MUST be bigger than 0!');
                    }

                    if(uvand.baDesc.FAAR) {
                        assert.isNumber(uvand.baDesc.FAAR, 'BiometricAccuracyDescriptor.FAAR MUST be of type number!');
                        assert.isAbove(uvand.baDesc.FAAR, 0, 'BiometricAccuracyDescriptor.FAAR MUST be bigger than 0!');
                    }

                    if(uvand.baDesc.maxReferenceDataSets) {
                        assert.isNumber(uvand.baDesc.maxReferenceDataSets, 'BiometricAccuracyDescriptor.maxReferenceDataSets MUST be of type number!');
                        assert.isAbove(uvand.baDesc.maxReferenceDataSets, 0, 'BiometricAccuracyDescriptor.maxReferenceDataSets MUST be bigger than 0!');
                    }

                    if(uvand.baDesc.maxRetries) {
                        assert.isNumber(uvand.baDesc.maxRetries, 'BiometricAccuracyDescriptor.maxRetries MUST be of type number!');
                        assert.isAbove(uvand.baDesc.maxRetries, 0, 'BiometricAccuracyDescriptor.maxRetries MUST be bigger than 0!');
                    }

                    if(uvand.baDesc.blockSlowdown) {
                        assert.isNumber(uvand.baDesc.blockSlowdown, 'BiometricAccuracyDescriptor.blockSlowdown MUST be of type number!');
                        assert.isAbove(uvand.baDesc.blockSlowdown, 0, 'BiometricAccuracyDescriptor.blockSlowdown MUST be bigger than 0!');
                    }
                }

                if(uvand.paDesc) {
                    assert.strictEqual(uvand.userVerification, USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_PATTERN, 'If "VerificationMethodDescriptor" contains "paDesc", then "userVerification" MUST be set be set to USER_VERIFY_PATTERN(0x00000080)');
                    assert.isObject(uvand.paDesc, 'PatternAccuracyDescriptor MUST be of type Dictionary!');

                    assert.isDefined(uvand.paDesc.minComplexity, 'PatternAccuracyDescriptor is missing "minComplexity" field!');
                    assert.isNumber(uvand.paDesc.minComplexity, 'PatternAccuracyDescriptor.minComplexity MUST be of type number!');
                    assert.isAbove(uvand.paDesc.minComplexity, 0, 'PatternAccuracyDescriptor.minComplexity MUST be bigger than 0!');

                    if(uvand.paDesc.maxRetries) {
                        assert.isNumber(uvand.paDesc.maxRetries, 'PatternAccuracyDescriptor.maxRetries MUST be of type number!');
                        assert.isAbove(uvand.paDesc.maxRetries, 0, 'PatternAccuracyDescriptor.maxRetries MUST be bigger than 0!');
                    }

                    if(uvand.paDesc.blockSlowdown) {
                        assert.isNumber(uvand.paDesc.blockSlowdown, 'PatternAccuracyDescriptor.blockSlowdown MUST be of type number!');
                        assert.isAbove(uvand.paDesc.blockSlowdown, 0, 'PatternAccuracyDescriptor.blockSlowdown MUST be bigger than 0!');
                    }
                }
            }
        }
    })

    it(`P-16

        Required Metadata to contain "keyProtection" field, that is of type Number.

        MUST be a 16-bit number representing the bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values [FIDORegistry].
        MUST not be zero. 
        Bitflag KEY_PROTECTION_SOFTWARE cannot be combined with KEY_PROTECTION_HARDWARE. 
        Bitflag KEY_PROTECTION_SOFTWARE cannot be combined with KEY_PROTECTION_TEE. 
        Bitflag KEY_PROTECTION_SOFTWARE cannot be combined with KEY_PROTECTION_SECURE_ELEMENT.

        Bitflag KEY_PROTECTION_TEE should be combined with KEY_PROTECTION_HARDWARE.
        Bitflag KEY_PROTECTION_SECURE_ELEMENT should be combined with KEY_PROTECTION_HARDWARE.

        Bitflag KEY_PROTECTION_REMOTE_HANDLE MUST be set if isSecondFactorOnly is set to true.

    `, () => {
        assert.isDefined(Metadata.keyProtection, 'Metadata is missing "keyProtection" field!');
        assert.isNumber(Metadata.keyProtection, 'Metadata.keyProtection MUST be of type Number!');
        assert.notStrictEqual(Metadata.keyProtection, 0, 'Metadata.keyProtection can not be 0!');

        /* 
            KEY_PROTECTION_SOFTWARE 0x01
            KEY_PROTECTION_HARDWARE 0x02
            KEY_PROTECTION_TEE 0x04
            KEY_PROTECTION_SECURE_ELEMENT 0x08
            KEY_PROTECTION_REMOTE_HANDLE 0x10
        */
        let tag = KEY_PROTECTION_TYPES[Metadata.keyProtection & 0x01] 
               || KEY_PROTECTION_TYPES[Metadata.keyProtection & 0x02] 
               || KEY_PROTECTION_TYPES[Metadata.keyProtection & 0x04] 
               || KEY_PROTECTION_TYPES[Metadata.keyProtection & 0x08]
               || KEY_PROTECTION_TYPES[Metadata.keyProtection & 0x10];

        assert.isDefined(tag, 'The number does not contain bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values!');

        assert.isNotTrue(!!(Metadata.keyProtection & 0x01 && Metadata.keyProtection & 0x02), 'Bitflag 0x01 cannot be combined with 0x02');
        assert.isNotTrue(!!(Metadata.keyProtection & 0x01 && Metadata.keyProtection & 0x04), 'Bitflag 0x01 cannot be combined with 0x04');
        assert.isNotTrue(!!(Metadata.keyProtection & 0x01 && Metadata.keyProtection & 0x08), 'Bitflag 0x01 cannot be combined with 0x08');

        if(Metadata.isSecondFactorOnly)
            assert.isTrue(!!(Metadata.keyProtection & 0x10), 'Bitflag 0x10 MUST be set if isSecondFactorOnly is set to true.');
        else
            assert.isNotTrue(!!(Metadata.keyProtection & 0x10), 'Bitflag 0x10 MUST NOT be set if isSecondFactorOnly is set to false.');
    })

    it(`P-17

        If "isKeyRestricted" is presented, it must be of type boolean.

    `, function() {
        if(Metadata.isKeyRestricted) {
            assert.isBoolean(Metadata.isKeyRestricted, 'isKeyRestricted MUST be of type BOOLEAN!');
        } else {
            this.skip()
        }
    })

    it(`P-18

        If "isFreshUserVerificationRequired" is presented, it must be of type boolean.

    `, function() {
        if(Metadata.isFreshUserVerificationRequired) {
            assert.isBoolean(Metadata.isFreshUserVerificationRequired, 'isFreshUserVerificationRequired MUST be of type BOOLEAN!');
        } else {
            this.skip()
        }
    })

    it(`P-19

        Required Metadata to contain "matcherProtection" field, that is of type Number.

        MUST be a 16-bit number representing the bit fields defined by the MATCHER_PROTECTION constants in the FIDO Registry of Predefined Values [FIDORegistry].
        MUST not be zero.

        Bitflag neither of MATCHER_PROTECTION_SOFTWARE, MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_ON_CHIP can be combined together

    `, () => {
        assert.isDefined(Metadata.matcherProtection, 'Metadata is missing "matcherProtection" field!');
        assert.isNumber(Metadata.matcherProtection, 'Metadata.matcherProtection MUST be of type Number!');
        assert.notStrictEqual(Metadata.matcherProtection, 0, 'Metadata.matcherProtection can not be 0!');

        assert.isDefined(MATCHER_PROTECTION_TYPES[Metadata.matcherProtection], 'Metadata.matcherProtection is not a valid MATCHER_PROTECTION constant!');
    })

    it(`P-20

        If Metadata contains "cryptoStrength" field, check that its of type number, and is NOT 0!

    `, function() {
        if(Metadata.cryptoStrength) {
            assert.isNumber(Metadata.cryptoStrength, 'Metadata.cryptoStrength MUST be of type Number!');
            assert.notStrictEqual(Metadata.cryptoStrength, 0, 'Metadata.cryptoStrength can NOT be 0!');
        } else {
            this.skip()
        }
    })

    it(`P-21

        If Metadata contains "operatingEnv" field, check that its of type DOMString, not empty, and its value is a member of FIDORestrictedOperatingEnv.

    `, function() {
        if(Metadata.operatingEnv) {
            assert.isString(Metadata.operatingEnv, 'Metadata.operatingEnv MUST be of type DOMString!');
            assert.isNotEmpty(Metadata.operatingEnv, 'Metadata.operatingEnv can NOT be empty!');
            assert.include(AUTHENTICATOR_ALLOWED_RESTRICTED_OPERATING_ENVIRONMENTS_LIST, Metadata.operatingEnv, 'Metadata.operatingEnv MUST be set to one of the allowed values in FIDORestrictedOperatingEnv!');
        } else {
            this.skip()
        }
    })

    it(`P-22

        Required "attachmentHint", of type unsigned long.
            MUST be a 32-bit number representing the bit fields defined by the ATTACHMENT_HINT constants in the FIDO Registry of Predefined Values [FIDORegistry].
            MUST not be zero.

            If bitflag ATTACHMENT_HINT_NFC or ATTACHMENT_HINT_BLUETOOTH is set, then ATTACHMENT_HINT_WIRELESS MUST be set as well.

            ATTACHMENT_HINT_READY MUST NOT be set

    `, () => {
        assert.isDefined(Metadata.attachmentHint, 'Metadata is missing "attachmentHint" field!');
        assert.isNumber(Metadata.attachmentHint, 'Metadata.attachmentHint MUST be of type Number!');
        assert.notStrictEqual(Metadata.attachmentHint, 0, 'Metadata.attachmentHint can not be 0!');

        /* 
            ATTACHMENT_HINT_INTERNAL 0x0001
            ATTACHMENT_HINT_EXTERNAL 0x0002
            ATTACHMENT_HINT_WIRED 0x0004
            ATTACHMENT_HINT_NETWORK 0x0040
            ATTACHMENT_HINT_WIRELESS 0x0008
            ATTACHMENT_HINT_NFC 0x0010
            ATTACHMENT_HINT_BLUETOOTH 0x0020
            ATTACHMENT_HINT_READY 0x0080

        */
        let tag = ATTACHMENT_HINTS[Metadata.attachmentHint & 0x0001] 
               || ATTACHMENT_HINTS[Metadata.attachmentHint & 0x0002] 
               || ATTACHMENT_HINTS[Metadata.attachmentHint & 0x0004] 
               || ATTACHMENT_HINTS[Metadata.attachmentHint & 0x0040]
               || ATTACHMENT_HINTS[Metadata.attachmentHint & 0x0008]
               || ATTACHMENT_HINTS[Metadata.attachmentHint & 0x0010]
               || ATTACHMENT_HINTS[Metadata.attachmentHint & 0x0020]
               || ATTACHMENT_HINTS[Metadata.attachmentHint & 0x0080];

        assert.isDefined(tag, 'The number does not contain bit fields defined by the ATTACHMENT_HINT constants in the FIDO Registry of Predefined Values!');

        if(!!(Metadata.attachmentHint & 0x0010 || Metadata.attachmentHint & 0x0020))
            assert.isTrue(!!(Metadata.attachmentHint & 0x0008), 'If either ATTACHMENT_HINT_BLUETOOTH or ATTACHMENT_HINT_NFC Bitflags are set, ATTACHMENT_HINT_WIRELESS MUST be set as well!')
    })

    it(`P-23
        Required Metadata to contain "isSecondFactorOnly" field MUST be true!
    `, () => {
        assert.isDefined(Metadata.isSecondFactorOnly, 'Metadata missing isSecondFactorOnly field!');
        assert.isBoolean(Metadata.isSecondFactorOnly, 'isSecondFactorOnly must be boolean!');
        assert.isTrue(Metadata.isSecondFactorOnly, 'For U2F isSecondFactorOnly MUST be set to True!');
    })

    it(`P-24

        For U2F tcDisplay MUST be set to 0

    `, () => {
        assert.isDefined(Metadata.tcDisplay, 'Metadata missing tcDisplay field!');
        assert.isNumber(Metadata.tcDisplay, 'Metadata.tcDisplay field MUST be of type number!');
        assert.strictEqual(Metadata.tcDisplay, 0, 'For U2F Metadata.tcDisplay MUST be set to 0!');
    })

    it(`P-25

        For U2F tcDisplayContentType MUST NOT be present!

    `, () => {
        assert.isUndefined(Metadata.tcDisplayContentType, 'For U2F tcDisplayContentType MUST NOT be present!');
    })

    it(`P-26

        For U2F tcDisplayPNGCharacteristics MUST NOT be present!

    `, () => {
        assert.isUndefined(Metadata.tcDisplayPNGCharacteristics, 'For U2F tcDisplayPNGCharacteristics MUST NOT be present!');
    })

    it(`P-27

        Required attestationRootCertificates, of type DOMString[]. 
        
        MUST be present and non-empty if attestationTypes contains other values than ATTESTATION_BASIC_SURROGATE.
        
        Each entry must be a Base64-encoded (section 4 of [[RFC4648]]), DER-encoded [[ITU-X690-2008]] PKIX certificate value.

    `, () => {
        assert.isDefined(Metadata.attestationRootCertificates, 'Metadata missing attestationRootCertificates field!');
        assert.isArray(Metadata.attestationRootCertificates, 'Metadata.attestationRootCertificates MUST be of type SEQUENCE!');
        if(Metadata.attestationTypes.indexOf(ATTESTATION_TYPES.ATTESTATION_BASIC_FULL) !== -1) {
            assert.isNotEmpty(Metadata.attestationRootCertificates, 'Metadata.attestationRootCertificates MUST not be empty!');
            for(let i = 0; i < Metadata.attestationRootCertificates.length; i++) {
                let attestationRootCertificate = Metadata.attestationRootCertificates[i];

                assert.match(attestationRootCertificate, /^[A-Za-z0-9+/]+[=]{0,2}$/, `certificate with index ${i} is not base64 encoded!`)

                let PEMCertificate = metadataAttestationCertToPEM(attestationRootCertificate);
                try {
                    let certificate = new jsrsasign.X509();
                    certificate.readCertPEM(PEMCertificate);
                } catch (e) {
                    throw new Error(`certificate with index ${i} is not a valid PKIX DER-encoded certificate!`)
                }
            }
        } else if(Metadata.attestationTypes.length === 1 && Metadata.attestationTypes[0] === ATTESTATION_TYPES.ATTESTATION_BASIC_SURROGATE) {
            assert.isEmpty(Metadata.attestationRootCertificates, 'Metadata.attestationRootCertificates MUST not be empty for ATTESTATION_BASIC_SURROGATE!');
        }
    })

    it(`P-28

        If "ecdaaTrustAnchors" field presented, it must be of type SEQUENCE, and for each EcdaaTrustAnchor entry check that: 
            "EcdaaTrustAnchor.X" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.Y" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.c" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.sx" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.sy" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.G1Curve" is of type DOMString, and its NOT empty.

    `, function() {
        assert.isUndefined(ecdaaTrustAnchors, 'For U2F, ecdaaTrustAnchors MUST be undefined!');
    })

    it(`P-29

        Required Metadata to contain "icon" field, of type DOMString, not empty, set to URL [RFC2397] encoded PNG

    `, () => {
        assert.isDefined(Metadata.icon, 'Metadata missing icon field!');
        assert.match(Metadata.icon, /^data:image\/png;base64,[A-Za-z0-9+/]+[=]{0,2}$/, 'MUST be PNG image URL encoded!')
    })

    it(`P-30

        Required supportedExtensions to be undefined!

    `, function() {
        assert.isUndefined(supportedExtensions, 'For U2F, supported extensions MUST be undefined!');
    })
})
