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

        Client-ASM-Protocol-1

        Test the ASMRequest in ASM API call

    `, function() {

    let authenticatorIndex = undefined;
    let metadata           = window.config.test.metadataStatement;
    before(function() {
        this.timeout(30000);
        let message = {
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'requestType':'GetInfo'
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                for(let AuthenticatorInfo of response.responseData.Authenticators) {
                    if (AuthenticatorInfo.aaid === metadata.aaid) {
                        authenticatorIndex = AuthenticatorInfo.authenticatorIndex;
                        return
                    }
                }

                throw new Error(`GetInfo did not return AuthenticatorInfo for Authenticator with AAID ${window.config.test.metadataStatement.aaid}!`)
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are successfully returning GetInfo for the tested authenticator, that is described by the metadata statement.\n\n The error is: ' + error);
            })
    });

    this.timeout(30000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1
        
        Send a valid GetInfo ASMRequest, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00), and for each of the AuthenticatorInfo in "responseData.Authenticators" check that:
                (a) "authenticatorIndex" is of type NUMBER
                (b) "asmVersions" is of type SEQUENCE, and contains members of type UPV, and is NOT empty!
                (c) "isUserEnrolled" is of type BOOLEAN
                (d) "hasSettings" is of type BOOLEAN
                (e) "aaid" is of type DOMString, and correctly formated{2 byte encoded in HEX}#{2 byte encoded in HEX}, e.g. FFFF#FC01
                (f) "assertionScheme" is of type DOMString, and is set to "UAFV1TLV"
                (g) "authenticationAlgorithm" is of type NUMBER, and is one of the ALG constants defined in Registry of Predefined Values [FIDORegistry]. 
                (h) "attestationTypes" is of type SEQUENCE, contains only TAG_ATTESTATION constants defined in Registry of Predefined Values [FIDORegistry]. 
                (i) "keyProtection" is of type NUMBER, and is one of the KEY_PROTECTION constants defined in Registry of Predefined Values [FIDORegistry]. 
                (j) "userVerification" is of type NUMBER, and is one of the USER_VERIFY constants defined in Registry of Predefined Values [FIDORegistry].
                (k) "matcherProtection" is of type NUMBER, and is one of the MATCHER_PROTECTION constants defined in Registry of Predefined Values [FIDORegistry].
                (l) "attachmentHint" is of type NUMBER, and is one of the ATTACHMENT_HINT constants defined in Registry of Predefined Values [FIDORegistry].
                (m) "isSecondFactorOnly" is of type BOOLEAN
                (n) "isRoamingAuthenticator" is of type BOOLEAN
                (o) "supportedExtensionIDs" is of type SEQUENCE, and contains only DOMString members
                (p) "tcDisplay" is of type NUMBER, and value is defined by the set TRANSACTION_CONFIRMATION_DISPLAY constants defined in Registry of Predefined Values [FIDORegistry].
                (q) If tcDisplay is not 0, "tcDisplayContentType" MUST be set to either "text/plain", or "image/png"
                (r) If tcDisplay is not 0, "tcDisplayPNGCharacteristics" MUST be of type SEQUENCE, and for each DisplayPNGCharacteristicsDescriptor check that:
                    (1) "width" field is NOT missing, and of type NUMBER 
                    (2) "height" field is NOT missing, and of type NUMBER 
                    (3) "bitDepth" field is NOT missing, and of type NUMBER 
                    (4) "colorType" field is NOT missing, and of type NUMBER 
                    (5) "compression" field is NOT missing, and of type NUMBER 
                    (6) "filter" field is NOT missing, and of type NUMBER 
                    (7) "interlace" field is NOT missing, and of type NUMBER 
                    (8) If "plte" is NOT missing, it must be of type SEQUENCE, and for each "rgbPalletteEntry" member check that: 
                    (i) "r" field is NOT missing, and is of type NUMBER 
                    (ii) "g" field is NOT missing, and is of type NUMBER 
                    (iii) "b" field is NOT missing, and is of type NUMBER 
                    (d) if "exts" field is presented, it must be of type SEQUENCE
                (s) If "title" is presented, it MUST be of type DOMString
                (t) If "description" is presented, it MUST be of type DOMString
                (u) If "icon" is presented, it MUST be of type DOMString, and MUST be  data URL [RFC2397] encoded [PNG]

    `, () => {
        let message = {
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'requestType':'GetInfo'
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK!`);

                for(let AuthenticatorInfo of response.responseData.Authenticators) {
                    if(AuthenticatorInfo.aaid === metadata.aaid) {
                        assert.isDefined(AuthenticatorInfo.authenticatorIndex, 'AuthenticatorInfo missing authenticatorIndex field!');
                        assert.isNumber(AuthenticatorInfo.authenticatorIndex, 'authenticatorIndex MUST be of type NUMBER!');

                    /* ----- ASMVersions ----- */
                        assert.isDefined(AuthenticatorInfo.asmVersions, 'AuthenticatorInfo missing asmVersions field!');
                        assert.isArray(AuthenticatorInfo.asmVersions, 'AuthenticatorInfo.asmVersions is not of type SEQUENCE!');
                        assert.isNotEmpty(AuthenticatorInfo.asmVersions, 'AuthenticatorInfo.asmVersions can NOT be empty!');
                        for(let asmVersion of AuthenticatorInfo.asmVersions) {
                            assert.isObject(asmVersion, 'Version MUST be of type OBJECT!');
                            assert.isDefined(asmVersion.major, 'Version MUST contain "major" key!');
                            assert.isNumber(asmVersion.major, 'Version.major MUST be of type Number!');
                            assert.isDefined(asmVersion.minor, 'Version MUST contain "minor" key!');
                            assert.isNumber(asmVersion.minor, 'Version.minor MUST be of type Number!');
                        }
                        assert.deepInclude(AuthenticatorInfo.asmVersions, {'major':1, 'minor':1}, 'AuthenticatorInfo.asmVersions MUST include v1.1!');

                    /* ----- isUserEnrolled ----- */
                        assert.isDefined(AuthenticatorInfo.isUserEnrolled, 'AuthenticatorInfo missing isUserEnrolled field!');
                        assert.isBoolean(AuthenticatorInfo.isUserEnrolled, 'isUserEnrolled MUST be of type BOOLEAN, and MUST not be missing!');

                    /* ----- hasSettings ----- */
                        assert.isDefined(AuthenticatorInfo.hasSettings, 'AuthenticatorInfo missing hasSettings field!');
                        assert.isBoolean(AuthenticatorInfo.hasSettings, 'AuthenticatorInfo.hasSettings is not of type BOOLEAN!');

                    /* ----- aaid ----- */
                        assert.isDefined(AuthenticatorInfo.aaid, 'AuthenticatorInfo missing aaid field!');
                        assert.isString(AuthenticatorInfo.aaid, 'AuthenticatorInfo.aaid is not of type STRING!');
                        assert.match(AuthenticatorInfo.aaid, /^[a-fA-F0-9]{4}#[a-fA-F0-9]{4}$/, `AAID ${AuthenticatorInfo.aaid} is not in format {2 byte encoded in HEX}#{2 byte encoded in HEX}!`);

                    /* ----- assertionScheme ----- */
                        assert.isDefined(AuthenticatorInfo.assertionScheme, 'AuthenticatorInfo missing assertionScheme field!');
                        assert.isString(AuthenticatorInfo.assertionScheme, 'AuthenticatorInfo.assertionScheme is not of type STRING!');
                        assert.strictEqual(AuthenticatorInfo.assertionScheme, 'UAFV1TLV', 'AuthenticatorInfo.assertionScheme MUST be set to UAFV1TLV!');

                    /* ----- authenticationAlgorithm ----- */
                        assert.isDefined(AuthenticatorInfo.authenticationAlgorithm, 'authenticationAlgorithm MUST NOT be missing!');
                        assert.isNumber(AuthenticatorInfo.authenticationAlgorithm, 'authenticationAlgorithm MUST be of type NUMBER!');
                        assert.isDefined(AUTHENTICATION_ALGORITHMS[AuthenticatorInfo.authenticationAlgorithm], `authenticationAlgorithm is not set to one of the algorihtms specified in Registry of Predefined Values!`);
                        assert.strictEqual(AuthenticatorInfo.authenticationAlgorithm, metadata.authenticationAlgorithm, 'AuthenticatorInfo.authenticationAlgorithm MUST match MetadataStatement.authenticationAlgorithm!');

                    /* ----- attestationTypes ----- */
                        assert.isDefined(AuthenticatorInfo.attestationTypes, 'AuthenticatorInfo missing attestationTypes field!');
                        assert.isArray(AuthenticatorInfo.attestationTypes, 'AuthenticatorInfo.attestationTypes is not of type SEQUENCE');
                        assert.isTrue(AuthenticatorInfo.attestationTypes.length > 0, 'attestationTypes cannot be empty!');
                        assert.isTrue(AuthenticatorInfo.attestationTypes.indexOf(0x3E07) !== -1 || AuthenticatorInfo.attestationTypes.indexOf(0x3E08) !== -1, 'attestationTypes does not contain TAG_ATTESTATION_BASIC_FULL and TAG_ATTESTATION_BASIC_SURROGATE!');
                        assert.deepEqual(AuthenticatorInfo.attestationTypes, metadata.attestationTypes, 'AuthenticatorInfo.attestationTypes MUST match MetadataStatement.attestationTypes!');

                    /* ----- userVerification ----- */
                        assert.isDefined(AuthenticatorInfo.userVerification, 'AuthenticatorInfo missing userVerification field!');
                        assert.isNumber(AuthenticatorInfo.userVerification, 'AuthenticatorInfo.userVerification is not of type Number!');
                        assert.include(getMetadataUserVerificationCombos(), AuthenticatorInfo.userVerification, 'MetadataStatement.userVerificationDetails AND combos MUST contain AuthenticatorInfo.userVerification!');

                    /* ----- keyProtection ----- */
                        assert.isDefined(AuthenticatorInfo.keyProtection, 'AuthenticatorInfo missing keyProtection field!');
                        assert.isNumber(AuthenticatorInfo.keyProtection, 'AuthenticatorInfo.keyProtection is not of type Number!');
                        assert.strictEqual(AuthenticatorInfo.keyProtection, metadata.keyProtection, 'AuthenticatorInfo.keyProtection MUST match MetadataStatement.keyProtection!');
                        assert.notStrictEqual(AuthenticatorInfo.keyProtection, 0, 'AuthenticatorInfo.keyProtection can not be 0!');
                        let tag = KEY_PROTECTION_TYPES[AuthenticatorInfo.keyProtection & 0x01] 
                               || KEY_PROTECTION_TYPES[AuthenticatorInfo.keyProtection & 0x02] 
                               || KEY_PROTECTION_TYPES[AuthenticatorInfo.keyProtection & 0x04] 
                               || KEY_PROTECTION_TYPES[AuthenticatorInfo.keyProtection & 0x08]
                               || KEY_PROTECTION_TYPES[AuthenticatorInfo.keyProtection & 0x10];
                        assert.isDefined(tag, 'The number does not contain bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values!');
                        assert.isNotTrue(!!(AuthenticatorInfo.keyProtection & 0x01 && AuthenticatorInfo.keyProtection & 0x02), 'Bitflag 0x01 cannot be combined with 0x02');
                        assert.isNotTrue(!!(AuthenticatorInfo.keyProtection & 0x01 && AuthenticatorInfo.keyProtection & 0x04), 'Bitflag 0x01 cannot be combined with 0x04');
                        assert.isNotTrue(!!(AuthenticatorInfo.keyProtection & 0x01 && AuthenticatorInfo.keyProtection & 0x08), 'Bitflag 0x01 cannot be combined with 0x08');

                        if(AuthenticatorInfo.isSecondFactorOnly)
                            assert.isTrue(!!(AuthenticatorInfo.keyProtection & 0x10), 'Bitflag 0x10 MUST be set if isSecondFactorOnly is set to true.');
                        else
                            assert.isNotTrue(!!(AuthenticatorInfo.keyProtection & 0x10), 'Bitflag 0x10 MUST NOT be set if isSecondFactorOnly is set to false.');

                    /* ----- matcherProtection ----- */
                        assert.isDefined(AuthenticatorInfo.matcherProtection, 'AuthenticatorInfo missing matcherProtection field!');
                        assert.isNumber(AuthenticatorInfo.matcherProtection, 'AuthenticatorInfo.matcherProtection is not of type Number!');
                        assert.isDefined(MATCHER_PROTECTION_TYPES[AuthenticatorInfo.matcherProtection], 'matcherProtection is not set to one of the algorihtms specified in Registry of Predefined Values!');
                        assert.strictEqual(AuthenticatorInfo.matcherProtection, metadata.matcherProtection, 'AuthenticatorInfo.matcherProtection MUST match MetadataStatement.matcherProtection!');

                    /* ----- attachmentHint ----- */
                        assert.isDefined(AuthenticatorInfo.attachmentHint, 'AuthenticatorInfo missing attachmentHint field!');
                        assert.isNumber(AuthenticatorInfo.attachmentHint, 'AuthenticatorInfo.attachmentHint is not of type Number!');
                        assert.isDefined(AUTHENTICATOR_ATTACHMENT_HINTS[AuthenticatorInfo.attachmentHint], 'attachmentHint is not set to one of the algorihtms specified in Registry of Predefined Values!');
                        assert.strictEqual(AuthenticatorInfo.attachmentHint, metadata.attachmentHint, 'AuthenticatorInfo.attachmentHint MUST match MetadataStatement.attachmentHint!');

                    /* ----- isSecondFactorOnly ----- */
                        assert.isDefined(AuthenticatorInfo.isSecondFactorOnly, 'AuthenticatorInfo missing isSecondFactorOnly field!');
                        assert.isBoolean(AuthenticatorInfo.isSecondFactorOnly, 'AuthenticatorInfo.isSecondFactorOnly is not of type BOOLEAN');
                        assert.strictEqual(AuthenticatorInfo.isSecondFactorOnly, metadata.isSecondFactorOnly, 'AuthenticatorInfo.isSecondFactorOnly MUST match MetadataStatement.isSecondFactorOnly!');

                    /* ----- isRoamingAuthenticator ----- */
                        assert.isDefined(AuthenticatorInfo.isRoamingAuthenticator, 'AuthenticatorInfo missing isRoamingAuthenticator field!');
                        assert.isBoolean(AuthenticatorInfo.isRoamingAuthenticator, 'AuthenticatorInfo.isRoamingAuthenticator is not of type BOOLEAN!');

                        assert.isDefined(AuthenticatorInfo.supportedExtensionIDs, 'AuthenticatorInfo missing supportedExtensionIDs field!');
                        assert.isArray(AuthenticatorInfo.supportedExtensionIDs, 'AuthenticatorInfo.supportedExtensionIDs is not of type SEQUENCE!');
                        for(let extensionID of AuthenticatorInfo.supportedExtensionIDs)
                            assert.isString(extensionID, 'ExtensionID MUST be of type STRING!');

                        assert.isDefined(AuthenticatorInfo.tcDisplay, 'AuthenticatorInfo missing tcDisplay field!');
                        assert.isNumber(AuthenticatorInfo.tcDisplay, 'AuthenticatorInfo.tcDisplay is not of type Number!');
                        assert.strictEqual(AuthenticatorInfo.tcDisplay, metadata.tcDisplay, 'AuthenticatorInfo.tcDisplay MUST match MetadataStatement.tcDisplay!');
                        if(AuthenticatorInfo.tcDisplay !== 0) {
                            let tcDisplayCopy = AuthenticatorInfo.tcDisplay;
                            for(let key in TRANSACTION_CONFIRMATION_DISPLAY_TYPES_TO_INT) {
                                if(!!(TRANSACTION_CONFIRMATION_DISPLAY_TYPES_TO_INT[key] & AuthenticatorInfo.tcDisplay))
                                    tcDisplayCopy = tcDisplayCopy - TRANSACTION_CONFIRMATION_DISPLAY_TYPES_TO_INT[key];
                            }

                            assert.strictEqual(tcDisplayCopy, 0, 'AuthenticatorInfo.tcDisplay bit flags been set to unsupported flags!');
                            assert.isDefined(AuthenticatorInfo.tcDisplayContentType, 'AuthenticatorInfo missing tcDisplayContentType field!');
                            assert.include(['text/plain', 'image/png'], AuthenticatorInfo.tcDisplayContentType, 'tcDisplayContentType must be either text/plain or image/png!');
                        }

                        if(AuthenticatorInfo.tcDisplay !== 0 && AuthenticatorInfo.tcDisplayContentType === 'image/png') {
                            assert.isDefined(AuthenticatorInfo.tcDisplayPNGCharacteristics, 'AuthenticatorInfo missing tcDisplayPNGCharacteristics field!');
                            assert.isArray(AuthenticatorInfo.tcDisplayPNGCharacteristics, 'AuthenticatorInfo.tcDisplayPNGCharacteristics MUST be a SEQUENCE!');
                
                            for(let DisplayPNGCharacteristicsDescriptor of AuthenticatorInfo.tcDisplayPNGCharacteristics) {
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
                        }

                        if(AuthenticatorInfo.tcDisplay === 0) {
                            assert.isUndefined(AuthenticatorInfo.tcDisplayContentType, 'If AuthenticatorInfo.tcDisplay set to NO_DISPLAY(0), AuthenticatorInfo.tcDisplayContentType MUST be missing!');
                            assert.isUndefined(AuthenticatorInfo.tcDisplayPNGCharacteristics, 'If AuthenticatorInfo.tcDisplay set to NO_DISPLAY(0), AuthenticatorInfo.tcDisplayPNGCharacteristics MUST be missing!');
                        }

                        if(AuthenticatorInfo.icon) {
                            assert.isString(AuthenticatorInfo.icon, 'AuthenticatorInfo.icon is not of type STRING!');
                            assert.isNotEmpty(AuthenticatorInfo.icon, 'AuthenticatorInfo.icon MUST not be empty!');
                            assert.match(AuthenticatorInfo.icon, /^data:image\/png;base64,[A-Za-z0-9+/]+[=]{0,2}$/, 'AuthenticatorInfo.icon MUST be URL encoded PNG image!');
                        }

                        if(AuthenticatorInfo.title) {
                            assert.isString(AuthenticatorInfo.title, 'AuthenticatorInfo.title is not of type STRING!');
                            assert.isNotEmpty(AuthenticatorInfo.title, 'title can not be empty!')
                        }

                        if(AuthenticatorInfo.description) {
                            assert.isString(AuthenticatorInfo.description, 'AuthenticatorInfo.description is not of type STRING!');
                            assert.isNotEmpty(AuthenticatorInfo.description, 'AuthenticatorInfo.description MUST not be empty!');
                        }

                    }
                }
            })
    })

    it(`P-2
        
        Send a valid OpenSettings ASMRequest, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00) 

    `)

    describe(`F-1
        
        Send three ASM Requests, with "requestType" set to null, undefined, and empty DOMString, wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01) 

    `, () => {
        it('requestType is NULL', () => {
            let message = {
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'requestType': null,
                'authenticatorIndex': authenticatorIndex
            }

            return window.navigator.fido.uafasm.processASMRequest(message)
                .then((response) => {
                    assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                    assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('requestType is UNDEFINED', () => {
            let message = {
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'requestType': undefined,
                'authenticatorIndex': authenticatorIndex
            }

            return window.navigator.fido.uafasm.processASMRequest(message)
                .then((response) => {
                    assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                    assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('requestType is EMPTY DOMString', () => {
            let message = {
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'requestType': '',
                'authenticatorIndex': authenticatorIndex
            }

            return window.navigator.fido.uafasm.processASMRequest(message)
                .then((response) => {
                    assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                    assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-2
        
        Send ASM Request with "requestType" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01) 

    `, () => {
        let message = {
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'requestType': generateRandomTypeExcluding('string'),
            'authenticatorIndex': authenticatorIndex
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    it(`F-3
        
        Send ASM Request with "asmVersion" that is NOT of type DICTIONARY, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01) 

    `, () => {
        let message = {
            'asmVersion': generateRandomTypeExcluding('object'),
            'requestType': 'GetRegistrations',
            'authenticatorIndex': authenticatorIndex
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    describe(`F-4
        
        Send two ASM Requests, with "version.major" set to null and undefined, wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)   

    `, () => {
        it('version.major is NULL', () => {
            let message = {
                'asmVersion': {
                    'major': null,
                    'minor': 1
                },
                'requestType': 'GetRegistrations',
                'authenticatorIndex': authenticatorIndex
            }

            return window.navigator.fido.uafasm.processASMRequest(message)
                .then((response) => {
                    assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                    assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('version.major is UNDEFINED', () => {
            let message = {
                'asmVersion': {
                    'minor': 1
                },
                'requestType': 'GetRegistrations',
                'authenticatorIndex': authenticatorIndex
            }

            return window.navigator.fido.uafasm.processASMRequest(message)
                .then((response) => {
                    assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                    assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    describe(`F-5
        
        Send two ASM Requests, with "version.minor" set to null and undefined, wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)   

    `, () => {
        it('version.minor is NULL', () => {
            let message = {
                'asmVersion': {
                    'major': 1,
                    'minor': null
                },
                'requestType': 'GetRegistrations',
                'authenticatorIndex': authenticatorIndex
            }

            return window.navigator.fido.uafasm.processASMRequest(message)
                .then((response) => {
                    assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                    assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('version.minor is UNDEFINED', () => {
            let message = {
                'asmVersion': {
                    'major': 1
                },
                'requestType': 'GetRegistrations',
                'authenticatorIndex': authenticatorIndex
            }

            return window.navigator.fido.uafasm.processASMRequest(message)
                .then((response) => {
                    assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                    assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-6
        
        Send ASM Request with "asmVersion.major" that is NOT of type NUMBER, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)   

    `, () => {
        let message = {
            'asmVersion': {
                'major': generateRandomTypeExcluding('number'),
                'minor': 1
            },
            'requestType': 'GetRegistrations',
            'authenticatorIndex': authenticatorIndex
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    it(`F-7
        
        Send ASM Request with "asmVersion.minor" that is NOT of type NUMBER, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)   

    `, () => {
        let message = {
            'asmVersion': {
                'major': 1,
                'minor': generateRandomTypeExcluding('number')
            },
            'requestType': 'GetRegistrations',
            'authenticatorIndex': authenticatorIndex
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    it(`F-8
        
        Send ASM Request with "authenticatorIndex" that is NOT of type NUMBER, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01) 

    `, () => {
        let message = {
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'requestType': 'GetRegistrations',
            'authenticatorIndex': generateRandomTypeExcluding('number')
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    it(`F-9
        
        Send ASM Request with "args" that is NOT of type DICTIONARY, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)   

    `, () => {
        let message = {
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'requestType': 'Register',
            'authenticatorIndex': authenticatorIndex,
            'args': generateRandomTypeExcluding('number')
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    it(`F-10
        
        Send ASM Request with "exts" that is NOT of type SEQUENCE, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01) 

    `, () => {
        let message = {
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'requestType': 'GetRegistrations',
            'authenticatorIndex': authenticatorIndex,
            'exts': generateRandomTypeExcluding('number')
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                assert.isDefined(response.statusCode, 'Response missing statusCode field!');
                assert.strictEqual(response.statusCode, 0x01, `ASM returned wrong statusCode ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })
})
