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

        Verify compliance of metadata statement fields.

    `, function() {

    let metadata = window.config.test.metadataStatement;

/* ---------- Positive Tests ---------- */
    it(`P-1
        Required "aaid", of type AAID.
            MUST be in format of {2 byte encoded in HEX}#{2 byte encoded in HEX}, e.g. FFFF#FC01
    `, () => {
        assert.match(metadata.aaid, /^[a-fA-F0-9]{4}#[a-fA-F0-9]{4}$/, `aaid ${metadata.aaid} is not in format {2 byte encoded in HEX}#{2 byte encoded in HEX}!`);
    })

    it(`P-2
        Required "description", of type DOMString.
    `, () => {
        assert.isString(metadata.description, 'description field is not a DOMString!');
        assert.isTrue(metadata.description.length > 0, 'description cannot be empty!');
    })

    it(`P-3

        If "protocolFamily" field is presented, it must be of type DOMString, and equal to "uaf".

    `, () => {
        if(metadata.protocolFamily) {
            assert.isString(metadata.protocolFamily, 'protocolFamily field MUST be of type DOMString!');
            assert.isNotEmpty(metadata.protocolFamily, 'protocolFamily MUST not be empty!');
            assert.strictEqual(metadata.protocolFamily, 'uaf', 'protocolFamily MUST be set to "uaf"');
        }
    })

    it(`P-4
        Required "authenticatorVersion", of type unsigned short.
    `, () => {
        assert.isNumber(metadata.authenticatorVersion, 'authenticatorVersion MUST be a number!');
    })

    it(`P-5
        Required "upv", of type Version[].
            MUST not be empty.
            MUST contain { "major": 1, "minor": 1 }.
    `, () => {
        assert.isTrue(metadata.upv.length > 0, 'upv cannot be empty!');
        assert.deepInclude(metadata.upv, { 'major': 1, 'minor': 1 }, 'upv does not contain { "major": 1, "minor": 1 }!');
    })

    it(`P-6
        Required "assertionScheme", of type DOMString.
            MUST be "UAFV1TLV".
    `, () => {
        assert.strictEqual(metadata.assertionScheme, 'UAFV1TLV', 'assertionScheme MUST be set to UAFV1TLV!');
    })

    it(`P-7
        Required "authenticationAlgorithm", of type unsigned short. 
            MUST be one of the ALG constants defined in Registry of Predefined Values [FIDORegistry].
            MUST not be zero.
    `, () => {
        assert.isDefined(metadata.authenticationAlgorithm, 'metadata missing authenticationAlgorithm field!');
        assert.isDefined(AUTHENTICATION_ALGORITHMS[metadata.authenticationAlgorithm], `authenticationAlgorithm is not set to one of the algorihtms specified in Registry of Predefined Values!`);
    })

    it(`P-8
        Required "publicKeyAlgAndEncoding", of type unsigned short.
            MUST be one of the ALG_KEY constants defined in Registry of Predefined Values [FIDORegistry].
            MUST not be zero.
    `, () => {
        assert.isDefined(metadata.publicKeyAlgAndEncoding, 'metadata missing publicKeyAlgAndEncoding field!');
        assert.isDefined(PUBLIC_KEY_REPRESENTATION_FORMATS[metadata.publicKeyAlgAndEncoding], `publicKeyAlgAndEncoding is not set to one of the algorihtms specified in Registry of Predefined Values!`);
    })

    it(`P-9
        Required "attestationTypes", of type unsigned short[], each list entry.
            MUST be one of the TAG_ATTESTATION constants defined in Registry of Predefined Values [UAFRegistry]. 
            MUST not be an empty list.
    `, () => {
        assert.isTrue(metadata.attestationTypes.length > 0, 'attestationTypes cannot be empty!');
        assert.isTrue(metadata.attestationTypes.indexOf(0x3E07) !== -1 || metadata.attestationTypes.indexOf(0x3E08) !== -1, 'attestationTypes does not contain TAG_ATTESTATION_BASIC_FULL and TAG_ATTESTATION_BASIC_SURROGATE!')
    })

    it(`P-10
        Required "userVerificationDetails", of type VerificationMethodANDCombinations[]. 
            MUST not be an empty list.
    `, () => {
        assert.isTrue(metadata.userVerificationDetails.length > 0, 'userVerificationDetails cannot be empty!');
    })

    it(`P-11

        If "isKeyRestricted" is presented, it must be of type boolean.

    `, () => {
        if(metadata.isKeyRestricted) {
            assert.isBoolean(metadata.isKeyRestricted, 'isKeyRestricted MUST be of type BOOLEAN!');
        }
    })

    it(`P-12

        If "isFreshUserVerificationRequired" is presented, it must be of type boolean.

    `, () => {
        if(metadata.isFreshUserVerificationRequired) {
            assert.isBoolean(metadata.isFreshUserVerificationRequired, 'isFreshUserVerificationRequired MUST be of type BOOLEAN!');
        }
    })

    it(`P-13
        Required "keyProtection", of type unsigned short. 
            MUST be a 16-bit number representing the bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values [FIDORegistry].
            MUST not be zero. 
            Bitflag 0x01 cannot be combined with 0x02. 
            Bitflag 0x01 cannot be combined with 0x04. 
            Bitflag 0x01 cannot be combined with 0x08.

            Bitflag 0x04 should be combined with 0x02.
            Bitflag 0x08 should be combined with 0x02.

            Bitflag 0x10 MUST be set if isSecondFactorOnly is set to true.
    `, () => {
        assert.notStrictEqual(metadata.keyProtection, 0, 'metadata.keyProtection can not be 0!');

        let tag = KEY_PROTECTION_TYPES[metadata.keyProtection & 0x01] 
               || KEY_PROTECTION_TYPES[metadata.keyProtection & 0x02] 
               || KEY_PROTECTION_TYPES[metadata.keyProtection & 0x04] 
               || KEY_PROTECTION_TYPES[metadata.keyProtection & 0x08]
               || KEY_PROTECTION_TYPES[metadata.keyProtection & 0x10];

        assert.isDefined(tag, 'The number does not contain bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values!');

        assert.isNotTrue(!!(metadata.keyProtection & 0x01 && metadata.keyProtection & 0x02), 'Bitflag 0x01 cannot be combined with 0x02');
        assert.isNotTrue(!!(metadata.keyProtection & 0x01 && metadata.keyProtection & 0x04), 'Bitflag 0x01 cannot be combined with 0x04');
        assert.isNotTrue(!!(metadata.keyProtection & 0x01 && metadata.keyProtection & 0x08), 'Bitflag 0x01 cannot be combined with 0x08');

        if(metadata.isSecondFactorOnly)
            assert.isTrue(!!(metadata.keyProtection & 0x10), 'Bitflag 0x10 MUST be set if isSecondFactorOnly is set to true.');
        else
            assert.isNotTrue(!!(metadata.keyProtection & 0x10), 'Bitflag 0x10 MUST NOT be set if isSecondFactorOnly is set to false.');
    })

    it(`P-14
        Required "matcherProtection", of type unsigned short.
            MUST be a 16-bit number representing the bit fields defined by the MATCHER_PROTECTION constants in the FIDO Registry of Predefined Values [FIDORegistry].
            MUST not be zero.
    `, () => {
        assert.isDefined(metadata.matcherProtection, 'metadata missing matcherProtection field!');
        assert.isDefined(MATCHER_PROTECTION_TYPES[metadata.matcherProtection], 'matcherProtection is not set to one of the algorihtms specified in Registry of Predefined Values!');
    })

    it(`P-15
        Required "attachmentHint", of type unsigned long.
            MUST be a 32-bit number representing the bit fields defined by the ATTACHMENT_HINT constants in the FIDO Registry of Predefined Values [FIDORegistry].
            MUST not be zero.
    `, () => {
        assert.isDefined(metadata.attachmentHint, 'metadata is missing "attachmentHint" field!');
        assert.isNumber(metadata.attachmentHint, 'metadata.attachmentHint MUST be of type Number!');
        assert.notStrictEqual(metadata.attachmentHint, 0, 'metadata.attachmentHint can not be 0!');

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
        let tag = AUTHENTICATOR_ATTACHMENT_HINTS[metadata.attachmentHint & 0x0001] 
               || AUTHENTICATOR_ATTACHMENT_HINTS[metadata.attachmentHint & 0x0002] 
               || AUTHENTICATOR_ATTACHMENT_HINTS[metadata.attachmentHint & 0x0004] 
               || AUTHENTICATOR_ATTACHMENT_HINTS[metadata.attachmentHint & 0x0040]
               || AUTHENTICATOR_ATTACHMENT_HINTS[metadata.attachmentHint & 0x0008]
               || AUTHENTICATOR_ATTACHMENT_HINTS[metadata.attachmentHint & 0x0010]
               || AUTHENTICATOR_ATTACHMENT_HINTS[metadata.attachmentHint & 0x0020]
               || AUTHENTICATOR_ATTACHMENT_HINTS[metadata.attachmentHint & 0x0080];

        assert.isDefined(tag, 'The number does not contain bit fields defined by the ATTACHMENT_HINT constants in the FIDO Registry of Predefined Values!');

        if(!!(metadata.attachmentHint & 0x0010 || metadata.attachmentHint & 0x0020))
            assert.isTrue(!!(metadata.attachmentHint & 0x0008), 'If either ATTACHMENT_HINT_BLUETOOTH or ATTACHMENT_HINT_NFC Bitflags are set, ATTACHMENT_HINT_WIRELESS MUST be set as well!')
    })

    it(`P-16
        Required isSecondFactorOnly, of type boolean.
    `, () => {
        assert.isDefined(metadata.isSecondFactorOnly, 'metadata missing isSecondFactorOnly field!');
        assert.isBoolean(metadata.isSecondFactorOnly, 'isSecondFactorOnly must be boolean!');
    })

    it(`P-17

        Required tcDisplay, of type unsigned short.
            MUST be a 16-bit number representing the bit fields defined by the TRANSACTION_CONFIRMATION_DISPLAY constants in the FIDO Registry of Predefined Values [FIDORegistry].
            MUST be zero if transaction confirmation is not supported by the authenticator.

    `, () => {
        assert.isDefined(metadata.tcDisplay, 'metadata missing tcDisplay field!');
        assert.isNumber(metadata.tcDisplay, 'metadata field MUST be of type number!');

        if(metadata.tcDisplay !== 0) {
            let tcDisplayCopy = metadata.tcDisplay;
            for(let key in TRANSACTION_CONFIRMATION_DISPLAY_TYPES_TO_INT) {
                if(!!(TRANSACTION_CONFIRMATION_DISPLAY_TYPES_TO_INT[key] & metadata.tcDisplay))
                    tcDisplayCopy = tcDisplayCopy - TRANSACTION_CONFIRMATION_DISPLAY_TYPES_TO_INT[key];
            }

            assert.strictEqual(tcDisplayCopy, 0, 'tcDisplay bit flags set to unsupported flags!');
        }
    })

    it(`P-18
        Required tcDisplayContentType, of type DOMString.
            MUST be present if tcDisplay is non-zero.
            MUST be set to one of the supported MIME content type [RFC2049] for the transaction confirmation display, such as text/plain or image/png.
    `, () => {
        if(metadata.tcDisplay !== 0) {
            assert.isDefined(metadata.tcDisplayContentType, 'metadata missing tcDisplayContentType field!');
            assert.isTrue(metadata.tcDisplayContentType.length > 0, 'tcDisplayContentType cannot be empty!');
            assert.include(['text/plain', 'image/png'], metadata.tcDisplayContentType, 'tcDisplayContentType must be either text/plain or image/png.');
        } else {
            assert.isUndefined(metadata.tcDisplayContentType, 'tcDisplayContentType is defined when tcDisplay is set to NO_DISPLAY');
        }
    })

    it(`P-19
        Required tcDisplayPNGCharacteristics, of type DisplayPNGCharacteristicsDescriptor[].
            MUST be present and non-empty if tcDisplay is non-zero and tcDisplayContentType is image/png.
    `, () => {
        if(metadata.tcDisplay !== 0 && metadata.tcDisplayContentType === 'image/png') {
            assert.isDefined(metadata.tcDisplayPNGCharacteristics, 'metadata missing tcDisplayPNGCharacteristics field!');
            assert.isArray(metadata.tcDisplayPNGCharacteristics, 'tcDisplayPNGCharacteristics MUST be a SEQUENCE!');
            
            for(let DisplayPNGCharacteristicsDescriptor of metadata.tcDisplayPNGCharacteristics) {
                assert.isNumber(DisplayPNGCharacteristicsDescriptor.width, 'DisplayPNGCharacteristicsDescriptor.width MUST be a NUMBER!');
                assert.isNumber(DisplayPNGCharacteristicsDescriptor.height, 'DisplayPNGCharacteristicsDescriptor.height MUST be a NUMBER!');
                assert.isNumber(DisplayPNGCharacteristicsDescriptor.bitDepth, 'DisplayPNGCharacteristicsDescriptor.bitDepth MUST be a NUMBER!');
                assert.isNumber(DisplayPNGCharacteristicsDescriptor.colorType, 'DisplayPNGCharacteristicsDescriptor.colorType MUST be a NUMBER!');
                assert.isNumber(DisplayPNGCharacteristicsDescriptor.compression, 'DisplayPNGCharacteristicsDescriptor.compression MUST be a NUMBER!');
                assert.isNumber(DisplayPNGCharacteristicsDescriptor.filter, 'DisplayPNGCharacteristicsDescriptor.filter MUST be a NUMBER!');
                assert.isNumber(DisplayPNGCharacteristicsDescriptor.interlace, 'DisplayPNGCharacteristicsDescriptor.interlace MUST be a NUMBER!');

                if (DisplayPNGCharacteristicsDescriptor.plte !== undefined) {
                    assert.isArray(DisplayPNGCharacteristicsDescriptor.plte, 'DisplayPNGCharacteristicsDescriptor.plte MUST be a SEQUENCE!');

                    for (let PLTE of DisplayPNGCharacteristicsDescriptor.plte) {
                        assert.isNumber(PLTE.r, 'PLTE.r MUST be a NUMBER!');
                        assert.isNumber(PLTE.g, 'PLTE.g MUST be a NUMBER!');
                        assert.isNumber(PLTE.b, 'PLTE.b MUST be a NUMBER!');
                    }
                }
            }
        } else if(metadata.tcDisplay === 0) {
            assert.isUndefined(metadata.tcDisplayPNGCharacteristics, 'tcDisplayPNGCharacteristics MUST NOT be defined when tcDisplay is set to NO_DISPLAY!');
        }
    })

    it(`P-20
        Required attestationRootCertificates, of type DOMString[]. 
            MUST be present and non-empty if attestationTypes contains other values than TAG_ATTESTATION_BASIC_SURROGATE.
            Each entry must be a Base64-encoded (section 4 of [[RFC4648]]), DER-encoded [[ITU-X690-2008]] PKIX certificate value.
    `, () => {
        assert.isDefined(metadata.attestationRootCertificates, 'Metadata missing attestationRootCertificates field!');
        assert.isArray(metadata.attestationRootCertificates, 'Metadata.attestationRootCertificates MUST be of type SEQUENCE!');

        for(let i = 0; i < metadata.attestationRootCertificates.length; i++) {
            let attestationRootCertificate = metadata.attestationRootCertificates[i];

            assert.match(attestationRootCertificate, /^[A-Za-z0-9+/]+[=]{0,2}$/, `certificate with index ${i} is not base64 encoded!`)

            let PEMCertificate = metadataAttestationCertToPEM(attestationRootCertificate);
            try {
                let certificate = new jsrsasign.X509();
                certificate.readCertPEM(PEMCertificate);
            } catch (e) {
                throw new Error(`certificate with index ${i} is not a valid PKIX DER-encoded certificate!`)
            }
        }
    })

    it(`P-21

        If "ecdaaTrustAnchors" field presented, it must be of type SEQUENCE, and for each EcdaaTrustAnchor entry check that: 
            "EcdaaTrustAnchor.X" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.Y" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.c" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.sx" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.sy" is of type DOMString, and its NOT empty. 
            "EcdaaTrustAnchor.G1Curve" is of type DOMString, and its NOT empty.

    `, () => {
        if(metadata.ecdaaTrustAnchors) {
            assert.isArray(metadata.ecdaaTrustAnchors, 'ecdaaTrustAnchors field MUST be of type SEQUENCE!');

            for(let EcdaaTrustAnchor of metadata.ecdaaTrustAnchors) {
                assert.isDefined(EcdaaTrustAnchor.X, 'EcdaaTrustAnchor missing "X" field!');
                assert.isString(EcdaaTrustAnchor.X, 'EcdaaTrustAnchor.X MUST be of type DOMString!');
                assert.isNotEmpty(EcdaaTrustAnchor.X, 'EcdaaTrustAnchor.X MUST MUST not be empty');

                assert.isDefined(EcdaaTrustAnchor.Y, 'EcdaaTrustAnchor missing "Y" field!');
                assert.isString(EcdaaTrustAnchor.Y, 'EcdaaTrustAnchor.Y MUST be of type DOMString!');
                assert.isNotEmpty(EcdaaTrustAnchor.Y, 'EcdaaTrustAnchor.Y MUST MUST not be empty');

                assert.isDefined(EcdaaTrustAnchor.c, 'EcdaaTrustAnchor missing "c" field!');
                assert.isString(EcdaaTrustAnchor.c, 'EcdaaTrustAnchor.c MUST be of type DOMString!');
                assert.isNotEmpty(EcdaaTrustAnchor.c, 'EcdaaTrustAnchor.c MUST MUST not be empty');

                assert.isDefined(EcdaaTrustAnchor.sx, 'EcdaaTrustAnchor missing "sx" field!');
                assert.isString(EcdaaTrustAnchor.sx, 'EcdaaTrustAnchor.sx MUST be of type DOMString!');
                assert.isNotEmpty(EcdaaTrustAnchor.sx, 'EcdaaTrustAnchor.sx MUST MUST not be empty');

                assert.isDefined(EcdaaTrustAnchor.sy, 'EcdaaTrustAnchor missing "sy" field!');
                assert.isString(EcdaaTrustAnchor.sy, 'EcdaaTrustAnchor.sy MUST be of type DOMString!');
                assert.isNotEmpty(EcdaaTrustAnchor.sy, 'EcdaaTrustAnchor.sy MUST MUST not be empty');

                assert.isDefined(EcdaaTrustAnchor.G1Curve, 'EcdaaTrustAnchor missing "G1Curve" field!');
                assert.isString(EcdaaTrustAnchor.G1Curve, 'EcdaaTrustAnchor.G1Curve MUST be of type DOMString!');
                assert.isNotEmpty(EcdaaTrustAnchor.G1Curve, 'EcdaaTrustAnchor.G1Curve MUST MUST not be empty');
            }
        }
    })

    it(`P-22 icon
        Required, of type DOMString. 
            MUST contain A data: URL [RFC2397] encoded PNG.
            MUST not be empty.
    `, () => {
        assert.isDefined(metadata.icon, 'metadata missing icon field!');
        assert.match(metadata.icon, /^data:image\/png;base64,[A-Za-z0-9+/]+[=]{0,2}$/, 'MUST be PNG image URL encoded!')
    })

    it(`P-23 

        If "supportedExtensions" field presented, it must be of type SEQUENCE, and for each ExtensionDescriptor entry, check that: 
            (a) "ExtensionDescriptor.id" is NOT undefined, and of type DOMString, and NOT empty. 
            (b) If "ExtensionDescriptor.data" is NOT undefined, it must be of type DOMString 
            (c) "ExtensionDescriptor.fail_if_unknown" is NOT undefined, and of type BOOLEAN.

    `, () => {
        if(metadata.supportedExtensions) {
            assert.isArray(metadata.supportedExtensions, 'Supported extensions MUST be of type SEQUENCE');

            for(let ext of metadata.supportedExtensions) {
                assert.isDefined(ext.id, 'ExtensionDescriptor is missing "id" field!');
                assert.isString(ext.id, 'ExtensionDescriptor.id MUST be of type DOMString!');
                assert.isNotEmpty(ext.id, 'ExtensionDescriptor.id MUST not be empty!');

                assert.isDefined(ext.data, 'ExtensionDescriptor is missing "data" field!');
                assert.isString(ext.data, 'ExtensionDescriptor.data MUST be of type DOMString!');

                assert.isDefined(ext.fail_if_unknown, 'ExtensionDescriptor is missing "fail_if_unknown" field!');
                assert.isBoolean(ext.fail_if_unknown, 'ExtensionDescriptor.fail_if_unknown MUST be of type BOOLEAN!');
            }
        }
    })
})