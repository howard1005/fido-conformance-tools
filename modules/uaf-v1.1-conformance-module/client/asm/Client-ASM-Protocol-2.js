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

        Client-ASM-Protocol-2

        Test the Register command in ASM API call

    `, function() {

    let authenticatorIndex = undefined;
    let metadata           = window.config.test.metadataStatement;
    let username           = generateRandomString();
    let keyID              = undefined;
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

                throw new Error(`GetInfo did not return AuthenticatorInfo for Authenticator with AAID ${metadata.aaid}!`)
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are successfully returning GetInfo for the tested authenticator, that is described by the metadata statement.\n\n The error is: ' + error);
            })
    })

    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    })

    this.timeout(30000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1
        
        Send a valid Register ASMRequest, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00). Check that "RegisterOut.assertionScheme" equal to "UAFV1TLV". Decode "RegisterOut.assertion" field base64url encoded TLV, and check that:
            (a) TLV does NOT have any leftover bytes
            (b) TAG_UAFV1_REG_ASSERTION is a member of the TLV 
            (c) TAG_UAFV1_KRD is a member of the TAG_UAFV1_REG_ASSERTION
            (d) TAG_AAID is a member of the TAG_UAFV1_KRD, MUST be nine(9) bytes long, and is decodes to the vendor AAID
            (e) TAG_ASSERTION_INFO is a member of the TAG_UAFV1_KRD, is seven(7) bytes long and:
                (1) "AuthenticatorVersion" MUST be equal to Metadata.authenticatorVersion
                (2) "AuthenticationMode" MUST be 0x01
                (3) "SignatureAlgAndEncoding" MUST be equal to Metadata.authenticationAlgorithm
                (4) "PublicKeyAlgAndEncoding" MUST be equal to Metadata.publicKeyAlgAndEncoding
            (f) TAG_FINAL_CHALLENGE_HASH is a member TAG_UAFV1_KRD, and is a SHA256 HASH of the FinalChallengeParams
            (e) TAG_KEYID is a member of the TAG_UAFV1_KRD, and it is at least 32 bytes long
            (f) TAG_COUNTERS is a member of the TAG_UAFV1_KRD, and it is eight(8) bytes long
            (g) TAG_PUB_KEY is a member of the TAG_UAFV1_KRD

    `, () => {
        let RegistrationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'attestationType': metadata.attestationTypes[0],
                'finalChallenge': generateRandomFinalChallenge(),
                'username': generateRandomString()
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Register'
        }

        return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                let RegisterOut = response.responseData;

                assert.strictEqual(RegisterOut.assertionScheme, 'UAFV1TLV', 'RegisterOut.assertionScheme MUST be set to "UAFV1TLV"!');
                assert.isTrue(isValidBase64URLString(RegisterOut.assertion), 'RegisterOut.assertion is NOT a valid BASE64URL encoded buffer!');

                let TLVBUFFER = base64url.decode(RegisterOut.assertion);
                let TAG_UAFV1_REG_ASSERTION_BUFFER = tlv.parser.searchTAG(TLVBUFFER, 'TAG_UAFV1_REG_ASSERTION');

                assert.strictEqual(TAG_UAFV1_REG_ASSERTION_BUFFER.bufferLength, TLVBUFFER.bufferLength, 'Buffer MUST not have any leftover bytes!')

                let TLVSTRUCT    = tlv.parser.parse(TLVBUFFER);
                let TLVSTRUCTRAW = tlv.parser.parseButSkipValueDecoding(TLVBUFFER);

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION, 'TLV missing TAG_UAFV1_REG_ASSERTION');
                assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD, 'TAG_UAFV1_REG_ASSERTION missing TAG_UAFV1_KRD');
                assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_AAID, 'TAG_UAFV1_KRD missing TAG_AAID');
                assert.strictEqual(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_AAID, metadata.aaid, `TAG_UAFV1_KRD.TAG_AAID(${TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_AAID}) MUST equal to Metadata.aaid(${metadata.aaid})`);
                
                assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO, 'TAG_UAFV1_KRD missing TAG_ASSERTION_INFO');

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO, 'TAG_UAFV1_KRD missing TAG_ASSERTION_INFO');
                assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.byteLength, 7, 'TAG_KEYID MUST be exactly seven(7) long');
                assert.strictEqual(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.AuthenticatorVersion, metadata.authenticatorVersion, `TAG_ASSERTION_INFO.AuthenticatorVersion(${TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.AuthenticatorVersion}) MUST equal to Metadata.authenticatorVersion(${metadata.authenticatorVersion})`);
                assert.strictEqual(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.AuthenticationMode, 0x01, `TAG_ASSERTION_INFO.AuthenticationMode(${TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.AuthenticationMode}) MUST be 0x01`);

                assert.strictEqual(
                    TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.SignatureAlgAndEncoding,
                    AUTHENTICATION_ALGORITHMS[metadata.authenticationAlgorithm],
                    
                    `TAG_ASSERTION_INFO.SignatureAlgAndEncoding(${TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.SignatureAlgAndEncoding}) MUST equal to Metadata.authenticationAlgorithm(${AUTHENTICATION_ALGORITHMS[metadata.authenticationAlgorithm]})`);

                assert.strictEqual(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.PublicKeyAlgAndEncoding, PUBLIC_KEY_REPRESENTATION_FORMATS[metadata.publicKeyAlgAndEncoding], `TAG_ASSERTION_INFO.PublicKeyAlgAndEncoding(${TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.PublicKeyAlgAndEncoding}) MUST equal to Metadata.authenticatorVersion(${PUBLIC_KEY_REPRESENTATION_FORMATS[metadata.publicKeyAlgAndEncoding]})`);

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_KEYID, 'TAG_UAFV1_KRD missing TAG_KEYID');
                assert.isAtLeast(TLVSTRUCTRAW.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_KEYID.byteLength, 32, 'TAG_KEYID MUST be at least 32 bytes long!');

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_COUNTERS, 'TAG_UAFV1_KRD missing TAG_COUNTERS');
                assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_COUNTERS.byteLength, 8, 'TAG_COUNTERS MUST be exactly eight(8) bytes long!');

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_PUB_KEY, 'TAG_UAFV1_KRD missing TAG_PUB_KEY');

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_FINAL_CHALLENGE_HASH, 'TAG_UAFV1_KRD missing TAG_FINAL_CHALLENGE_HASH');

                return window.crypto.subtle
                    .digest('SHA-256', stringToArrayBuffer(RegistrationRequest.args.finalChallenge))
                    .then((resultBuffer) => {
                        let result = base64url.encode(resultBuffer)

                        assert.strictEqual(result, TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_FINAL_CHALLENGE_HASH, `TAG_FINAL_CHALLENGE_HASH(${TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_FINAL_CHALLENGE_HASH}) MUST equal to SHA256 hash of FinalChallengeParams(${result})`);
                        
                        if(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL === undefined
                        && TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE === undefined) {
                            throw new Error('Neither TAG_ATTESTATION_BASIC_FULL nor TAG_ATTESTATION_BASIC_SURROGATE is presented!');
                        }
                    })

            })
    })

    it(`P-2
    
        If authenticator supports FULL attestation: Send a valid Register ASMRequest, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00), decode "RegisterOut.assertion" field base64url encoded TLV, and check that:
            (a) TAG_ATTESTATION_BASIC_FULL is a member of the TAG_UAFV1_REG_ASSERTION
            (b) TAG_SIGNATURE is a member of the TAG_ATTESTATION_BASIC_FULL
            (c) TAG_ATTESTATION_CERT is a member of the TAG_ATTESTATION_BASIC_FULL
            (d) TAG_SIGNATURE is a valid signature over TAG_UAFV1_KRD and can be verified using TAG_ATTESTATION_CERT

    `, function() {
        let RegistrationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'attestationType': metadata.attestationTypes[0],
                'finalChallenge': generateRandomFinalChallenge(),
                'username': generateRandomString()
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Register'
        }

        return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                let RegisterOut = response.responseData;
                let TLVBUFFER   = base64url.decode(RegisterOut.assertion);
                let TLVSTRUCT   = tlv.parser.parse(TLVBUFFER);

                if(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL !== undefined) {
                    assert.include(metadata.attestationTypes, TAG_DIR_TO_INT.TAG_ATTESTATION_BASIC_FULL, 'TAG_ATTESTATION_BASIC_FULL attestation been presented, however it is NOT a member of attestationTypes given in metadata statement!');

                    assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_SIGNATURE, 'TAG_ATTESTATION_BASIC_FULL missing TAG_UAFV1_KRD');
                    assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_ATTESTATION_CERT, 'TAG_ATTESTATION_BASIC_FULL missing TAG_UAFV1_KRD');

                    return verifyAssertion(RegisterOut.assertion)
                        .then((valid) => {
                            assert.isTrue(valid, 'The signature is invalid!')
                        })
                } else {
                    this.skip()
                }
            })
    })

    it(`P-3
    
        If authenticator supports SURROGATE attestation: Send a valid Register ASMRequest, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00), decode "RegisterOut.assertion" field base64url encoded TLV, and check that:
            (a) TAG_ATTESTATION_BASIC_SURROGATE is a member of the TAG_UAFV1_REG_ASSERTION
            (b) TAG_SIGNATURE is a member of the TAG_ATTESTATION_BASIC_SURROGATE
            (d) TAG_SIGNATURE is a valid signature over TAG_UAFV1_KRD and can be verified using TAG_PUB_KEY

    `, function() {
        let RegistrationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'attestationType': metadata.attestationTypes[0],
                'finalChallenge': generateRandomFinalChallenge(),
                'username': generateRandomString()
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Register'
        }

        return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                let RegisterOut = response.responseData;
                let TLVBUFFER   = base64url.decode(RegisterOut.assertion);
                let TLVSTRUCT   = tlv.parser.parse(TLVBUFFER);

                if(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE !== undefined) {
                    assert.include(metadata.attestationTypes, TAG_DIR_TO_INT.TAG_ATTESTATION_BASIC_SURROGATE, 'TAG_ATTESTATION_BASIC_SURROGATE attestation been presented, however it is NOT a member of attestationTypes given in metadata statement!');
                    assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE.TAG_SIGNATURE, 'TAG_ATTESTATION_BASIC_SURROGATE missing TAG_UAFV1_KRD');

                    return verifyAssertion(RegisterOut.assertion)
                        .then((valid) => {
                            assert.isTrue(valid, 'The signature is invalid!')
                        })
                } else {
                    this.skip()
                }
            })
    })

    it(`P-4

        Check that assertion contains TAG_ATTESTATION_BASIC_FULL and TAG_ATTESTATION_BASIC_SURROGATE, but not both

    `, function() {
        let RegistrationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'attestationType': metadata.attestationTypes[0],
                'finalChallenge': generateRandomFinalChallenge(),
                'username': generateRandomString()
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Register'
        }

        return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                let RegisterOut = response.responseData;
                let TLVBUFFER   = base64url.decode(RegisterOut.assertion);
                let TLVSTRUCT   = tlv.parser.parse(TLVBUFFER);

                assert.isTrue(!!TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL || !!TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE, 'Assertion does NOT contain neither FULL nor SURROGATE attestation!');

                assert.isNotTrue(!!TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL && !!TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE, 'Assertion can NOT contain both FULL and SURROGATE attestation!');
            })
    })

    describe(`P-5

        Run all Extensions tests from Protocol-Reg-Req-5 on an Register ASMRequest

    `, () => {
        it(`P-1

            Send a valid RegistrationRequest, with, exts SEQUENCE containing one valid Extension object, with id of "unknown-id", data, and fail_if_unknown to be false, wait for the response, and check that API does NOT return an error 

        `, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register',
                'exts': [
                    {
                        'id': 'unknown-id',
                        'data': '',
                        'fail_if_unknown': false
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);
                })
        })

        it(`F-1

            Send a valid RegistrationRequest, with, exts SEQUENCE containing one valid Extension object, with id of "unknown-id", data, and fail_if_unknown to be true, wait for the response, and check that API response returns UKNOWN(0xFF) error

        `, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register',
                'exts': [
                    {
                        'id': 'unknown-id',
                        'data': '',
                        'fail_if_unknown': true
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`F-2

            Send RegistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

        `, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register',
                'exts': [
                    {
                        'id': generateRandomTypeExcluding('string'),
                        'data': '',
                        'fail_if_unknown': true
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`F-3

            Send RegistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key length is larger than 32 characters, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

        `, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register',
                'exts': [
                    {
                        'id': 'some.extensions.very.long.id.that.is.keep.going.on.and.on',
                        'data': '',
                        'fail_if_unknown': false
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`F-4

            Send RegistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "data" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error    

        `, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register',
                'exts': [
                    {
                        'id': 'unknown-id',
                        'data': generateRandomTypeExcluding('string'),
                        'fail_if_unknown': false
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`F-5

            Send RegistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key is NOT of type BOOLEAN, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

        `, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register',
                'exts': [
                    {
                        'id': 'unknown-id',
                        'data': '',
                        'fail_if_unknown': generateRandomTypeExcluding('boolean')
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        describe(`F-6

            Send three RegistrationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "id" key set to "undefined", "null" and "empty" DOMString correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

        `, () => {
            it('Extension.id is undefined', () => {
                let RegistrationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'attestationType': metadata.attestationTypes[0],
                        'finalChallenge': generateRandomFinalChallenge(),
                        'username': generateRandomString()
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Register',
                    'exts': [
                        {
                            'id': undefined,
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Extension.id is null', () => {
                let RegistrationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'attestationType': metadata.attestationTypes[0],
                        'finalChallenge': generateRandomFinalChallenge(),
                        'username': generateRandomString()
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Register',
                    'exts': [
                        {
                            'id': null,
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Extension.id is empty DOMString', () => {
                let RegistrationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'attestationType': metadata.attestationTypes[0],
                        'finalChallenge': generateRandomFinalChallenge(),
                        'username': generateRandomString()
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Register',
                    'exts': [
                        {
                            'id': '',
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
        })

        describe(`F-7

            Send two RegistrationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "data" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

        `, () => {
            it('Extension.data is undefined', () => {
                let RegistrationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'attestationType': metadata.attestationTypes[0],
                        'finalChallenge': generateRandomFinalChallenge(),
                        'username': generateRandomString()
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Register',
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': undefined,
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Extension.data is null', () => {
                let RegistrationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'attestationType': metadata.attestationTypes[0],
                        'finalChallenge': generateRandomFinalChallenge(),
                        'username': generateRandomString()
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Register',
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': null,
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
        })

        describe(`F-8

            Send two RegistrationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

        `, () => {
            it('Extension.fail_if_unknown is undefined', () => {
                let RegistrationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'attestationType': metadata.attestationTypes[0],
                        'finalChallenge': generateRandomFinalChallenge(),
                        'username': generateRandomString()
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Register',
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': '',
                            'fail_if_unknown': undefined
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Extension.fail_if_unknown is null', () => {
                let RegistrationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'attestationType': metadata.attestationTypes[0],
                        'finalChallenge': generateRandomFinalChallenge(),
                        'username': generateRandomString()
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Register',
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': '',
                            'fail_if_unknown': null
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
        })
    })

    it(`P-6
        
        Send a valid GetRegistrations ASMRequest, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00), and for each of the AppRegistration in "responseData.appRegs", check that: 
            (a) "appID" field is of type DOMString, it's length is NOT zero(0) 
            (b) "keyIDs" field is of type SEQUENCE, and it contains at least one base64url encoded key

    `, () => {
        let message = {
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'requestType':'GetRegistrations',
            'authenticatorIndex': authenticatorIndex
        }

        return window.navigator.fido.uafasm.processASMRequest(message)
            .then((response) => {
                assert.isDefined(response.responseData, 'responseData is missing!');
                assert.isDefined(response.responseData.appRegs, 'GetRegistrationsOut is missing appRegs!');
                assert.isNotEmpty(response.responseData.appRegs, 'GetRegistrations response is empty!');
                
                for(let registration of response.responseData.appRegs) {
                    assert.isObject(registration, 'GetRegistrationsOut MUST only contain items of type DICTIONARY!');

                    assert.isDefined(registration.appID, 'AppRegistration.appID is undefined!');
                    assert.isString(registration.appID, 'AppRegistration.appID MUST be of type DOMString!');
                    assert.isNotEmpty(registration.appID, 'AppRegistration.appID is empty!');

                    assert.isDefined(registration.keyIDs, 'AppRegistration.keyIDs is undefined!');
                    assert.isArray(registration.keyIDs, 'AppRegistration.keyIDs MUST be of type SEQUENCE!');
                    assert.isNotEmpty(registration.keyIDs, 'AppRegistration.keyIDs is empty!');

                    for(let keyID of registration.keyIDs) {
                        assert.isString(keyID, 'KeyID MUST be of type DOMString!');
                        assert.isNotEmpty(keyID, 'KeyID MUST NOT be empty!');
                        assert.match(keyID, /^[a-zA-Z0-9_-]+$/, 'keyID MUST be base64URL(without padding) encoded!');
                    }
                }
            })
    })

/* ---------- Negative Tests ---------- */

    describe(`F-1

        Send three Register ASM Request with "RegisterIn.appID" set to undefined, null, and empty DOMString, wait for the responses, and check that each ASMResponse.statusCode eual to UAF_ASM_STATUS_ERROR(0x01)
    
    `, () => {
        it(`RegisterIn.appID is undefined`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': undefined,
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`RegisterIn.appID is null`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': null,
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`RegisterIn.appID is empty`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': '',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-2

        Send Register ASM Request with "RegisterIn.appID" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)
    
    `, () => {
        let RegistrationRequest = {
            'args': {
                'appID': generateRandomTypeExcluding('string'),
                'attestationType': metadata.attestationTypes[0],
                'finalChallenge': generateRandomFinalChallenge(),
                'username': generateRandomString()
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Register'
        }

        return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    describe(`F-3

        Send three Register ASM Request with "RegisterIn.username" set to null, undefined, and empty DOMString, wait for the responses, and check that each ASMResponse.statusCode eual to UAF_ASM_STATUS_ERROR(0x01)
    
    `, () => {
        it(`RegisterIn.username is undefined`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': undefined
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`RegisterIn.username is null`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': null
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`RegisterIn.username is empty`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': ''
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-4

        Send Register ASM Request with "RegisterIn.username" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)
    
    `, () => {
        let RegistrationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'attestationType': metadata.attestationTypes[0],
                'finalChallenge': generateRandomFinalChallenge(),
                'username': generateRandomTypeExcluding('string')
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Register'
        }

        return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    describe(`F-5

        Send three Register ASM Request with "RegisterIn.finalChallenge" set to null, undefined, and empty DOMString, wait for the responses, and check that each ASMResponse.statusCode eual to UAF_ASM_STATUS_ERROR(0x01)
    
    `, () => {
        it(`RegisterIn.finalChallenge is undefined`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': undefined,
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`RegisterIn.finalChallenge is null`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': null,
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`RegisterIn.finalChallenge is empty`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': metadata.attestationTypes[0],
                    'finalChallenge': '',
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-6

        Send Register ASM Request with "RegisterIn.finalChallenge" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)
    
    `, () => {
        let RegistrationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'attestationType': metadata.attestationTypes[0],
                'finalChallenge': generateRandomTypeExcluding('string'),
                'username': generateRandomString()
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Register'
        }

        return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    describe(`F-7

        Send two Register ASM Request with "RegisterIn.attestationType" set to null, undefined, wait for the responses, and check that each ASMResponse.statusCode eual to UAF_ASM_STATUS_ERROR(0x01)
    
    `, () => {
        it(`RegisterIn.attestationType is undefined`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': undefined,
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`RegisterIn.attestationType is null`, () => {
            let RegistrationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'attestationType': null,
                    'finalChallenge': generateRandomFinalChallenge(),
                    'username': generateRandomString()
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Register'
            }

            return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-8

        Send Register ASM Request with "RegisterIn.attestationType" that is NOT of type NUMBER, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        let RegistrationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'attestationType': generateRandomTypeExcluding('number'),
                'finalChallenge': generateRandomFinalChallenge(),
                'username': generateRandomString()
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Register'
        }

        return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })
    
    it(`F-9

        Send Register ASM Request with "RegisterIn.attestationType" is NOT set to the TAG_ATTESTATION_BASIC_FULL(0x3E07) nor TAG_ATTESTATION_BASIC_SURROGATE(0x3E08), wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        let RegistrationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'attestationType': 0x6969,
                'finalChallenge': generateRandomFinalChallenge(),
                'username': generateRandomString()
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Register'
        }

        return window.navigator.fido.uafasm.processASMRequest(RegistrationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })
})
