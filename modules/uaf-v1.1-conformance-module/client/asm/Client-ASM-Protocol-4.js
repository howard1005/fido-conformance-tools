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

        Client-ASM-Protocol-4

        Test the Deregister command in ASM API call

    `, function() {

    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    })

    let authenticatorIndex = undefined;
    let metadata           = window.config.test.metadataStatement;
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
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                for(let AuthenticatorInfo of response.responseData.Authenticators) {
                    if (AuthenticatorInfo.aaid === metadata.aaid) {
                        authenticatorIndex = AuthenticatorInfo.authenticatorIndex;
                    }
                }

                if(authenticatorIndex === undefined) {
                    throw new Error(`GetInfo did not return AuthenticatorInfo for Authenticator with AAID ${metadata.aaid}!`);
                }
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are successfully returning GetInfo for the tested authenticator, that is described by the metadata statement.\n\n The error is: ' + error);
            })
    })

    beforeEach(function() {
        this.timeout(30000);
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

                let TLVBUFFER = base64url.decode(RegisterOut.assertion);
                let TLVSTRUCT = tlv.parser.parse(TLVBUFFER);
                keyID         = TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_KEYID;
            })
    })

    this.timeout(30000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1
        
        Send a valid Deregister ASMRequest, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00)

    `, () => {
        let DeregisterRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'keyID': keyID
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Deregister'
        }

        return window.navigator.fido.uafasm.processASMRequest(DeregisterRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);
            })
    })

    it(`P-2
        
        Send a valid Deregister ASMRequest with unknown keyID, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00)

    `, () => {
        let DeregisterRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'keyID': base64url.encode(generateRandomBuffer(32))
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Deregister'
        }

        return window.navigator.fido.uafasm.processASMRequest(DeregisterRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);
            })
    })

    it(`P-3
        
        Send a valid Deregister ASMRequest with unknown appID, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00)

    `, () => {
        let DeregisterRequest = {
            'args': {
                'appID': 'android:apk-key-hash:' + base64.encode(generateRandomBuffer(32)),
                'keyID': base64url.encode(generateRandomBuffer(32))
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Deregister'
        }

        return window.navigator.fido.uafasm.processASMRequest(DeregisterRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);
            })
    })

    it(`P-4

        Send a valid Deregister ASMRequest with keyID field set to known keyID, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00). 
        Send a valid authentication request for any previously registered username, and check that ASMResponse.statusCode is UAF_ASM_STATUS_ACCESS_DENIED(0x02)

    `, () => {
        let DeregisterRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'keyID': keyID
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Deregister'
        }

        return window.navigator.fido.uafasm.processASMRequest(DeregisterRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
            })
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ACCESS_DENIED, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ACCESS_DENIED(0x02)!`);
            })
    })

/* --------- NEGATIVE TESTS ---------- */
    it(`F-1

        Send Deregister ASMRequest with "DeregisterIn.appID" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        let DeregisterRequest = {
            'args': {
                'appID': generateRandomTypeExcluding('string'),
                'keyID': keyID
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Deregister'
        }

        return window.navigator.fido.uafasm.processASMRequest(DeregisterRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    describe(`F-2

        Send three Deregister ASMRequest with "DeregisterIn.keyID" set to null, undefined, and empty DOMString, wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        it('DeregisterIn.keyID is null', () => {
            let DeregisterRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'keyID': null
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Deregister'
            }

            return window.navigator.fido.uafasm.processASMRequest(DeregisterRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('DeregisterIn.keyID is undefined', () => {
            let DeregisterRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'keyID': undefined
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Deregister'
            }

            return window.navigator.fido.uafasm.processASMRequest(DeregisterRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-3

        Send Deregister ASMRequest with "DeregisterIn.keyID" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        let DeregisterRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'keyID': generateRandomTypeExcluding('string')
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Deregister'
        }

        return window.navigator.fido.uafasm.processASMRequest(DeregisterRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })
})
