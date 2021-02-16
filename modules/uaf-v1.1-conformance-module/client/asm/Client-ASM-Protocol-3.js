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

        Client-ASM-Protocol-3

        Test the Authenticate command in ASM API call

    `, function() {

    let authenticatorIndex = undefined;
    let metadata           = window.config.test.metadataStatement;
    let keyID              = undefined;
    let userPublicKey      = undefined;
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
                        userPublicKey = window.extractPublicKeysFromAssertion(RegisterOut.assertion).publicKey;
                        keyID         = TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_KEYID;
                    })
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

    let textPlainTransaction = {
        'contentType': 'text/plain',
        'content': stringToBase64URL('THIS IS TEST AND ITS COMPLETELY NOT FUNNY, SO PLEASE ACCEPT THE TRANSACTION!')
    }

    let getTcDisplayPNGCharacteristics = () => {
        if(metadata.tcDisplayPNGCharacteristics)
            return jsonClone(metadata.tcDisplayPNGCharacteristics[0]);
    }

    let imagePNGTransaction = {
        'contentType': 'image/png',
        'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
        'tcDisplayPNGCharacteristics': getTcDisplayPNGCharacteristics()
    }

    let getBadTransaction = () => {
        if(metadata.tcDisplayContentType === 'text/plain')
            return jsonClone(textPlainTransaction);
        else if(metadata.tcDisplayContentType === 'image/png')
            return jsonClone(imagePNGTransaction);
        else
            throw new Error('MetadataStatementtcDisplayContentType is not set to neither "text/plain" nor to "image/png"!');
    }

    let getMixedTransaction = () => {
        if(metadata.tcDisplayContentType === 'text/plain')
            return jsonClone(imagePNGTransaction);
        else if(metadata.tcDisplayContentType === 'image/png')
            return jsonClone(textPlainTransaction);

        else
            throw new Error('MetadataStatementtcDisplayContentType is not set to neither "text/plain" nor to "image/png"!');
    }

/* ---------- Positive Tests ---------- */
    it(`P-1
        
        Send a valid Authenticate ASMRequest, wait for the response, and check ASMResponse.statusCode equal to  UAF_ASM_STATUS_OK(0x00). Check that "AuthenticateOut.assertionScheme" equal to "UAFV1TLV". Decode "AuthenticateOut.assertion" field base64url encoded TLV, and check that:
            (a) TLV does NOT have any leftover bytes
            (b) TAG_UAFV1_AUTH_ASSERTION is a member of the TLV 
            (c) TAG_UAFV1_SIGNED_DATA is a member of the TAG_UAFV1_AUTH_ASSERTION
            (d) TAG_AAID is a member of the TAG_UAFV1_SIGNED_DATA, MUST be nine(9) bytes long, and is decodes to the vendor AAID
            (e) TAG_ASSERTION_INFO is a member of the TAG_UAFV1_SIGNED_DATA, is five(5) bytes long and:
                (1) "AuthenticatorVersion" MUST be equal to Metadata.authenticatorVersion
                (2) "AuthenticationMode" MUST be 0x01
                (3) "SignatureAlgAndEncoding" MUST be equal to Metadata.authenticationAlgorithm
            (f) TAG_AUTHENTICATOR_NONCE is a member of the TAG_UAFV1_SIGNED_DATA, and it is at least eight(8) bytes long
            (g) TAG_FINAL_CHALLENGE_HASH is a member of the TAG_UAFV1_SIGNED_DATA, and is a SHA256 HASH of the FinalChallengeParams
            (h) TAG_TRANSACTION_CONTENT_HASH is a member of the TAG_UAFV1_SIGNED_DATA, and is a SHA256 HASH of the "Transaction.content", or if NOT Transaction been provided, it's length is zero(0)
            (i) TAG_KEYID is a member of the TAG_UAFV1_SIGNED_DATA, and it is at least 32 bytes long
            (j) TAG_COUNTERS is a member of the TAG_UAFV1_SIGNED_DATA, and it is four(4) bytes long
        

    `, () => {
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
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                let AuthenticateOut = response.responseData;

                assert.strictEqual(AuthenticateOut.assertionScheme, 'UAFV1TLV', 'assertionScheme MUST be UAFV1TLV!');
                assert.isString(AuthenticateOut.assertion, 'Assertion MUST be of type DOMString!');
                assert.isBelow(AuthenticateOut.assertion.length, 5460, 'Assertion MUST be shorter than 4096 bytes!');
                assert.match(AuthenticateOut.assertion, /^[a-zA-Z0-9_-]+$/, 'Assertion MUST be base64URL(without padding) encoded!');

                if(AuthenticateOut.exts !== undefined) {
                    assert.isArray(exts, 'exts MUST be a SEQUENCE!');
                }

                let TLVBUFFER = base64url.decode(AuthenticateOut.assertion);
                let TAG_UAFV1_AUTH_ASSERTION_BUFFER = tlv.parser.searchTAG(TLVBUFFER, 'TAG_UAFV1_AUTH_ASSERTION');

                assert.strictEqual(TAG_UAFV1_AUTH_ASSERTION_BUFFER.bufferLength, TLVBUFFER.bufferLength, 'Buffer MUST not have any leftover bytes!')

                let TLVSTRUCT = tlv.parser.parse(TLVBUFFER);
                let TLVSTRUCTRAW = tlv.parser.parseButSkipValueDecoding(TLVBUFFER);

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION, 'TLV missing TAG_UAFV1_AUTH_ASSERTION');
                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA, 'TAG_UAFV1_AUTH_ASSERTION missing TAG_UAFV1_SIGNED_DATA');

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_AAID, 'TAG_UAFV1_SIGNED_DATA missing TAG_AAID');
                assert.strictEqual(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_AAID, config.test.metadataStatement.aaid, `TAG_UAFV1_SIGNED_DATA.TAG_AAID(${TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_AAID}) MUST equal to Metadata.aaid(${config.test.metadataStatement.aaid})`);

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO, 'TAG_UAFV1_SIGNED_DATA missing TAG_ASSERTION_INFO');
                assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.byteLength, 5, 'TAG_ASSERTION_INFO MUST be at least five(5) bytes long!');
                assert.strictEqual(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.AuthenticatorVersion, config.test.metadataStatement.authenticatorVersion, `TAG_ASSERTION_INFO.AuthenticatorVersion(${TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.AuthenticatorVersion}) MUST equal to Metadata.authenticatorVersion(${config.test.metadataStatement.authenticatorVersion})`);
                assert.strictEqual(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.AuthenticationMode, 0x01, `TAG_ASSERTION_INFO.AuthenticationMode(${TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.AuthenticationMode}) MUST be 0x01`);
                assert.strictEqual(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.SignatureAlgAndEncoding, AUTHENTICATION_ALGORITHMS[window.config.test.metadataStatement.authenticationAlgorithm], `TAG_ASSERTION_INFO.SignatureAlgAndEncoding(${TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.SignatureAlgAndEncoding}) MUST equal to Metadata.authenticationAlgorithm(${AUTHENTICATION_ALGORITHMS[window.config.test.metadataStatement.authenticationAlgorithm]})`);

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_AUTHENTICATOR_NONCE, 'TAG_UAFV1_SIGNED_DATA missing TAG_AUTHENTICATOR_NONCE');
                assert.isAtLeast(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_AUTHENTICATOR_NONCE.byteLength, 8, 'TAG_AUTHENTICATOR_NONCE MUST be at least eight(8) bytes long!');

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH, 'TAG_UAFV1_SIGNED_DATA missing TAG_TRANSACTION_CONTENT_HASH');
                assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH.byteLength, 0, 'TAG_TRANSACTION_CONTENT_HASH MUST zero(0) bytes long!');
                
                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_KEYID, 'TAG_UAFV1_SIGNED_DATA missing TAG_KEYID');
                assert.isAtLeast(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_KEYID.byteLength, 32, 'TAG_KEYID MUST be at least 32 bytes long!');

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_COUNTERS, 'TAG_UAFV1_SIGNED_DATA missing TAG_COUNTERS');
                assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_COUNTERS.byteLength, 4, 'TAG_COUNTERS MUST be exactly eight(4) bytes long!');

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_FINAL_CHALLENGE_HASH, 'TAG_UAFV1_SIGNED_DATA missing TAG_FINAL_CHALLENGE_HASH');

                return crypto.subtle
                    .digest('SHA-256', stringToArrayBuffer(AuthenticationRequest.args.finalChallenge))
                    .then((resultBuffer) => {
                        let result = base64url.encode(resultBuffer)

                        assert.strictEqual(result, TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_FINAL_CHALLENGE_HASH, `TAG_FINAL_CHALLENGE_HASH(${TAG_FINAL_CHALLENGE_HASH}) MUST equal to SHA256 hash of FinalChallengeParams(${result})`);
                        
                        if(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE === undefined) {
                            throw new Error('TAG_SIGNATURE MUST be a member of TAG_UAFV1_AUTH_ASSERTION!');
                        }
                    })

            })
    })

    it(`P-2

        Send a valid Authenticate ASMRequest, wait for the response, and check ASMResponse.statusCode equal to 
                UAF_ASM_STATUS_OK(0x00). Check that "AuthenticateOut.assertionScheme" equal to "UAFV1TLV". Decode "AuthenticateOut.assertion" field base64url encoded TLV, and check that:
            (a) TAG_SIGNATURE is a member of the TAG_UAFV1_AUTH_ASSERTION
            (b) TAG_TRANSACTION_CONTENT_HASH length is zero(0)
            (d) TAG_SIGNATURE is a valid signature over TAG_UAFV1_SIGNED_DATA and can be verified using PublicKey saved from the registration.

    `, () => {
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
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                let AuthenticateOut = response.responseData;
                let TLVBUFFER = base64url.decode(AuthenticateOut.assertion);
                let TLVSTRUCT = tlv.parser.parse(TLVBUFFER);
                let TLVSTRUCTRAW = tlv.parser.parseButSkipValueDecoding(TLVBUFFER);

                assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH, 'TAG_UAFV1_SIGNED_DATA missing TAG_TRANSACTION_CONTENT_HASH');
                assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH.byteLength, 0, 'TAG_TRANSACTION_CONTENT_HASH MUST zero(0) bytes long!');

                return verifyAssertion(AuthenticateOut.assertion, userPublicKey)
                    .then((valid) => {
                        assert.isTrue(valid, 'The signature is invalid!')
                    })
            })
    })

    it(`P-3

        If Authenticator supports "text/plain" for Transaction confirmation: Send a valid Authenticate ASMRequest with a valid "text/plain" Transaction, wait for the response, and check ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00). Check that "AuthenticateOut.assertionScheme" equal to "UAFV1TLV". Decode "AuthenticateOut.assertion" field base64url encoded TLV, and check that:
            (a) TAG_SIGNATURE is a member of the TAG_UAFV1_AUTH_ASSERTION
            (b) TAG_TRANSACTION_CONTENT_HASH length is 32 bytes, and is a SHA256 HASH of the "Transaction.content"
            (d) TAG_SIGNATURE is a valid signature over TAG_UAFV1_SIGNED_DATA and can be verified using PublicKey saved from the registration.d signature over TAG_UAFV1_SIGNED_DATA and can be verified using PublicKey saved from the registration.

    `, function() {
        if(metadata.tcDisplay !== 0 && metadata.tcDisplayContentType === 'text/plain') {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [textPlainTransaction]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                    let AuthenticateOut = response.responseData;
                    let TLVBUFFER       = base64url.decode(AuthenticateOut.assertion);
                    let TLVSTRUCT       = tlv.parser.parse(TLVBUFFER);
                    let TLVSTRUCTRAW    = tlv.parser.parseButSkipValueDecoding(TLVBUFFER);

                    assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH, 'TAG_UAFV1_SIGNED_DATA missing TAG_TRANSACTION_CONTENT_HASH');
                    assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH.byteLength, 32, 'TAG_TRANSACTION_CONTENT_HASH MUST be exactly 32 bytes long!');

                    let promises = [];

                    let tcHashPromise = window.crypto.subtle
                        .digest('SHA-256', base64url.decode(textPlainTransaction.content))
                        .then((resultBuffer) => {
                            let result = base64url.encode(resultBuffer);

                            assert.strictEqual(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH, result, `TAG_TRANSACTION_CONTENT_HASH(${TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH}) does not equal to the hash of given transaction(${result})!`)
                        })

                    promises.push(tcHashPromise);

                    let verifyAssertionPromise = verifyAssertion(AuthenticateOut.assertion, userPublicKey)
                        .then((valid) => {
                            assert.isTrue(valid, 'The signature is invalid!')
                        })

                    promises.push(verifyAssertionPromise);

                    return Promise.all(promises)
                })
        } else {
            this.skip()
        }
    })

    it(`P-4

        If Authenticator supports "image/png" for Transaction confirmation: Send a valid Authenticate ASMRequest with a valid "image/png" Transaction, wait for the response, and check ASMResponse.statusCode equal to UAF_ASM_STATUS_OK(0x00). Check that "AuthenticateOut.assertionScheme" equal to "UAFV1TLV". Decode "AuthenticateOut.assertion" field base64url encoded TLV, and check that:
            (a) TAG_SIGNATURE is a member of the TAG_UAFV1_AUTH_ASSERTION
            (b) TAG_TRANSACTION_CONTENT_HASH length is 32 bytes, and is a SHA256 HASH of the "Transaction.content"
            (d) TAG_SIGNATURE is a valid signature over TAG_UAFV1_SIGNED_DATA and can be verified using PublicKey saved from the registration.

    `, function() {
        if(metadata.tcDisplay !== 0 && metadata.tcDisplayContentType === 'image/png') {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [imagePNGTransaction]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);

                    let AuthenticateOut = response.responseData;
                    let TLVBUFFER       = base64url.decode(AuthenticateOut.assertion);
                    let TLVSTRUCT       = tlv.parser.parse(TLVBUFFER);
                    let TLVSTRUCTRAW    = tlv.parser.parseButSkipValueDecoding(TLVBUFFER);

                    assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH, 'TAG_UAFV1_SIGNED_DATA missing TAG_TRANSACTION_CONTENT_HASH');
                    assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH.byteLength, 32, 'TAG_TRANSACTION_CONTENT_HASH MUST be exactly 32 bytes long!');

                    let promises = [];

                    let tcHashPromise = window.crypto.subtle
                        .digest('SHA-256', base64url.decode(imagePNGTransaction.content))
                        .then((resultBuffer) => {
                            let result = base64url.encode(resultBuffer);

                            assert.strictEqual(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH, result, `TAG_TRANSACTION_CONTENT_HASH(${TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH}) does not equal to the hash of given transaction(${result})!`)
                        })

                    promises.push(tcHashPromise);

                    let verifyAssertionPromise = verifyAssertion(AuthenticateOut.assertion, userPublicKey)
                        .then((valid) => {
                            assert.isTrue(valid, 'The signature is invalid!')
                        })

                    promises.push(verifyAssertionPromise);

                    return Promise.all(promises)
                })
        } else {
            this.skip()
        }
    })

    describe(`P-5

        Run all Extensions tests from Protocol-Reg-Req-5 on an Authenticate ASMRequest

    `, () => {
        it(`P-1

            Send a valid RegistrationRequest, with, exts SEQUENCE containing one valid Extension object, with id of "unknown-id", data, and fail_if_unknown to be false, wait for the response, and check that API does NOT return an error 

        `, () => {
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
                'requestType': 'Authenticate',
                'exts': [
                    {
                        'id': 'unknown-id',
                        'data': '',
                        'fail_if_unknown': false
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_OK, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_OK(0x00)!`);
                })
        })

        it(`F-1

            Send a valid RegistrationRequest, with, exts SEQUENCE containing one valid Extension object, with id of "unknown-id", data, and fail_if_unknown to be true, wait for the response, and check that API response returns UKNOWN(0xFF) error

        `, () => {
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
                'requestType': 'Authenticate',
                'exts': [
                    {
                        'id': 'unknown-id',
                        'data': '',
                        'fail_if_unknown': true
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`F-2

            Send RegistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

        `, () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': imagePNGTransaction
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate',
                'exts': [
                    {
                        'id': generateRandomTypeExcluding('string'),
                        'data': '',
                        'fail_if_unknown': true
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`F-3

            Send RegistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key length is larger than 32 characters, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

        `, () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': imagePNGTransaction
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate',
                'exts': [
                    {
                        'id': 'some.extensions.very.long.id.that.is.keep.going.on.and.on',
                        'data': '',
                        'fail_if_unknown': false
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`F-4

            Send RegistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "data" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error    

        `, () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': imagePNGTransaction
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate',
                'exts': [
                    {
                        'id': 'unknown-id',
                        'data': generateRandomTypeExcluding('string'),
                        'fail_if_unknown': false
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it(`F-5

            Send RegistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key is NOT of type BOOLEAN, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

        `, () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': imagePNGTransaction
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate',
                'exts': [
                    {
                        'id': 'unknown-id',
                        'data': '',
                        'fail_if_unknown': generateRandomTypeExcluding('boolean')
                    }
                ]
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        describe(`F-6

            Send three RegistrationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "id" key set to "undefined", "null" and "empty" DOMString correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

        `, () => {
            it('Extension.id is undefined', () => {
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': imagePNGTransaction
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate',
                    'exts': [
                        {
                            'id': undefined,
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Extension.id is null', () => {
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': imagePNGTransaction
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate',
                    'exts': [
                        {
                            'id': null,
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Extension.id is empty DOMString', () => {
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': imagePNGTransaction
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate',
                    'exts': [
                        {
                            'id': '',
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
        })

        describe(`F-7

            Send two RegistrationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "data" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

        `, () => {
            it('Extension.data is undefined', () => {
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': imagePNGTransaction
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate',
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': undefined,
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Extension.data is null', () => {
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': imagePNGTransaction
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate',
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': null,
                            'fail_if_unknown': false
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
        })

        describe(`F-8

            Send two RegistrationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

        `, () => {
            it('Extension.fail_if_unknown is undefined', () => {
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': imagePNGTransaction
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate',
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': '',
                            'fail_if_unknown': undefined
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Extension.fail_if_unknown is null', () => {
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': imagePNGTransaction
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate',
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': '',
                            'fail_if_unknown': null
                        }
                    ]
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
        })
    })

/* --------- Negative Tests -------- */

    describe(`F-1
    
        Send three Authenticate ASMRequest with "AuthenticateIn.appID" set to null, undefined, and empty DOMString, wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        it('AuthenticateIn.appID is null', () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': null,
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
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('AuthenticateIn.appID is undefined', () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': undefined,
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
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('AuthenticateIn.appID is null', () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': '',
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
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-2 

        Send Authenticate ASMRequest with "AuthenticateIn.appID" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        let AuthenticationRequest = {
            'args': {
                'appID': generateRandomTypeExcluding('string'),
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
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    it(`F-3

        If testing second-factor authenticator: Send Authenticate ASMRequest with "AuthenticateIn.keyIDs" set to "empty" SEQUENCE, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ACCESS_DENIED(0x02) or UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY(0x09)

    `, function() {
        if(metadata.isSecondFactorOnly === true) {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': []
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY(0x09)!`);
                })
        } else {
            this.skip()
        }
    })

    it(`F-4

        Send Authenticate ASMRequest with "AuthenticateIn.keyIDs" that is NOT of type SEQUENCE, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        let AuthenticationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'finalChallenge': generateRandomFinalChallenge(),
                'keyIDs': generateRandomTypeExcluding('array')
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Authenticate'
        }

        return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    describe(`F-5

        Send three Authenticate ASMRequest with "AuthenticateIn.finalChallenge" set to null, undefined, and empty DOMString, wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        it('AuthenticateIn.finalChallenge is null', () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': null,
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
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('AuthenticateIn.finalChallenge is undefined', () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': undefined,
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
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('AuthenticateIn.appID is empty', () => {
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': '',
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
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-6

        Send Authenticate ASMRequest with "AuthenticateIn.finalChallenge" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        let AuthenticationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'finalChallenge': generateRandomTypeExcluding('string'),
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
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    it(`F-7

        Send two Authenticate ASMRequest with "AuthenticateIn.transaction" set to null wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        let AuthenticationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'finalChallenge': generateRandomFinalChallenge(),
                'keyIDs': [
                    keyID
                ],
                'transaction': null
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Authenticate'
        }

        return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    it(`F-8

        Send Authenticate ASMRequest with "AuthenticateIn.transaction" that is NOT of type SEQUENCE, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, () => {
        let AuthenticationRequest = {
            'args': {
                'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                'finalChallenge': generateRandomFinalChallenge(),
                'keyIDs': [
                    keyID
                ],
                'transaction': generateRandomTypeExcluding('array')
            },
            'asmVersion': {
                'major': 1,
                'minor': 1
            },
            'authenticatorIndex': authenticatorIndex,
            'requestType': 'Authenticate'
        }

        return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
            .then((response) => {
                assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
            })
    })

    describe(`F-9

        Send three Authenticate ASMRequest with "Transaction.contentType" set to null, undefined, and empty DOMString, wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, function() {
        if(metadata.tcDisplay !== 0) {
            let badTransaction = getBadTransaction();

            it('Transaction.contentType is null', () => {
                badTransaction.contentType = null;
                let AuthenticationRequest  = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Transaction.contentType is undefined', () => {
                badTransaction.contentType = undefined;
                let AuthenticationRequest  = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('Transaction.contentType is empty', () => {
                badTransaction.contentType = '';
                let AuthenticationRequest  = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
        }
    })

    it(`F-10

        Send Authenticate ASMRequest with "Transaction.contentType" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, function() {
        if(metadata.tcDisplay !== 0) {
            let badTransaction = getBadTransaction();
            
            badTransaction.contentType = generateRandomTypeExcluding('string');    
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [badTransaction]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        } else {
            this.skip()
        }
    })

    it(`F-11

        Send Authenticate ASMRequest with "Transaction.contentType" is NOT set to type supported by the authenticator, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, function() {
        if(metadata.tcDisplay !== 0) {
            let mixedUpTransactions = getMixedTransaction();
            
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [mixedUpTransactions]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        } else {
            this.skip()
        }
    })

    describe(`F-12

        Send three Authenticate ASMRequest with "Transaction.content" set to null, undefined, and empty DOMString, wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, function() {
        before(function() {
            if(metadata.tcDisplay === 0)
                this.skip();
        })
        
        let badTransaction = getBadTransaction();
        it('Transaction.content is null', () => {
            badTransaction.content = null;
            let AuthenticationRequest  = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [badTransaction]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('Transaction.content is undefined', () => {
            badTransaction.content = undefined;
            let AuthenticationRequest  = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [badTransaction]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })

        it('Transaction.content is empty', () => {
            badTransaction.content = '';
            let AuthenticationRequest  = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [badTransaction]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        })
    })

    it(`F-13

        Send Authenticate ASMRequest with "Transaction.content" that is NOT of type DOMString, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, function() {
        if(metadata.tcDisplay !== 0) {
            let badTransaction = getBadTransaction();

            badTransaction.content = generateRandomTypeExcluding('string');    
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [badTransaction]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        } else {
            this.skip()
        }
    })

    it(`F-14

        If Authenticator supports "text/plain" for Transaction confirmation: Send Authenticate ASMRequest with "Transaction.content" set to base64url encoded text that is longer than 200 characters, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, function() {
        if(metadata.tcDisplay !== 0 && metadata.tcDisplayContentType === 'text/plain') {
            let badTransaction = getBadTransaction();

            badTransaction.content = stringToBase64URL(`The user ${generateRandomName()}, who is a friend of ${generateRandomName()}, who is the friend of ${generateRandomName()} who is the business partner of ${generateRandomName()} would like to transfer 200$ to ${generateRandomName()}. Do you accept this transaction?`); 

            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [badTransaction]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        } else {
            this.skip()
        }
    })

    it(`F-15

        If Authenticator supports "image/png" for Transaction confirmation: Send Authenticate ASMRequest with "Transaction.content" set to base64url encoded image, that is incorrectly PNG encoded, wait for the response, and check that ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, function() {
        if(metadata.tcDisplay !== 0 && metadata.tcDisplayContentType === 'image/png') {
            let badTransaction = getBadTransaction();

            badTransaction.content = generateRandomString(200);
            let AuthenticationRequest = {
                'args': {
                    'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                    'finalChallenge': generateRandomFinalChallenge(),
                    'keyIDs': [
                        keyID
                    ],
                    'transaction': [badTransaction]
                },
                'asmVersion': {
                    'major': 1,
                    'minor': 1
                },
                'authenticatorIndex': authenticatorIndex,
                'requestType': 'Authenticate'
            }

            return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                .then((response) => {
                    assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                })
        } else {
            this.skip()
        }
    })

    describe(`F-16

        If Authenticator supports "image/png" for Transaction confirmation: Send Authenticate ASMRequest with "Transaction.tcDisplayPNGCharacteristics":
            (a) tcDisplayPNGCharacteristics.width that is NOT of type NUMBER
            (b) tcDisplayPNGCharacteristics.width is undefined
            (c) tcDisplayPNGCharacteristics.height that is NOT of type NUMBER
            (d) tcDisplayPNGCharacteristics.height is undefined
            (e) tcDisplayPNGCharacteristics.bitDepth that is NOT of type NUMBER
            (f) tcDisplayPNGCharacteristics.bitDepth is undefined
            (g) tcDisplayPNGCharacteristics.colorType that is NOT of type NUMBER
            (h) tcDisplayPNGCharacteristics.colorType is undefined
            (i) tcDisplayPNGCharacteristics.compression that is NOT of type NUMBER
            (j) tcDisplayPNGCharacteristics.compression is undefined
            (k) tcDisplayPNGCharacteristics.filter that is NOT of type NUMBER
            (l) tcDisplayPNGCharacteristics.filter is undefined
            (m) tcDisplayPNGCharacteristics.interlace that is NOT of type NUMBER
            (n) tcDisplayPNGCharacteristics.interlace is undefined
            (o) tcDisplayPNGCharacteristics.plte that is NOT of type SEQUENCE
            (p) tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with missing "r" field
            (q) tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with "r" field is NOT of type NUMBER
            (r) tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with missing "g" field
            (s) tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with "g" field is NOT of type NUMBER
            (t) tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with missing "b" field
            (u) tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with "b" field is NOT of type NUMBER
            wait for the responses, and check that each ASMResponse.statusCode equal to UAF_ASM_STATUS_ERROR(0x01)

    `, function() {
        if(metadata.tcDisplay !== 0 && metadata.tcDisplayContentType === 'image/png') {
            it('tcDisplayPNGCharacteristics.width that is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.width = generateRandomTypeExcluding('number');
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.width is undefined', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.width = undefined;
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.height that is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.height = generateRandomTypeExcluding('number');
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.height is undefined', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.height = undefined;
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.bitDepth that is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.bitDepth = generateRandomTypeExcluding('number');
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.bitDepth is undefined', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.bitDepth = undefined;
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.colorType that is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.colorType = generateRandomTypeExcluding('number');
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.colorType is undefined', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.colorType = undefined;
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.compression that is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.compression = generateRandomTypeExcluding('number');
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.compression is undefined', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.compression = undefined;
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.filter that is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.filter = generateRandomTypeExcluding('number');
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.filter is undefined', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.filter = undefined;
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.interlace that is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.interlace = generateRandomTypeExcluding('number');
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.interlace is undefined', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.interlace = undefined;
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.plte that is NOT of type SEQUENCE', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.plte = generateRandomTypeExcluding('array');
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with missing "r" field', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.plte = [
                    {
                        'g': 0xbb,
                        'b': 0xcc
                    }
                ];
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with "r" field is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.plte = [
                    {
                        'r': generateRandomTypeExcluding('number'),
                        'g': 0xbb,
                        'b': 0xcc
                    }
                ];
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with missing "g" field', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.plte = [
                    {   
                        'r': 0xaa,
                        'b': 0xcc
                    }
                ];
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with "g" field is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.plte = [
                    {
                        'r': 0xaa,
                        'g': generateRandomTypeExcluding('number'),
                        'b': 0xcc
                    }
                ];
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })

            it('tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with missing "b" field', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.plte = [
                    {
                        'r': 0xaa,
                        'g': 0xbb
                    }
                ];
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
            it('tcDisplayPNGCharacteristics.plte contains "rgbPalletteEntry" with "b" field is NOT of type NUMBER', () => {
                let badTransaction = getBadTransaction();

                badTransaction.tcDisplayPNGCharacteristics.plte = [
                    {
                        'r': 0xaa,
                        'g': 0xbb,
                        'b': generateRandomTypeExcluding('number')
                    }
                ];
                let AuthenticationRequest = {
                    'args': {
                        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
                        'finalChallenge': generateRandomFinalChallenge(),
                        'keyIDs': [
                            keyID
                        ],
                        'transaction': [badTransaction]
                    },
                    'asmVersion': {
                        'major': 1,
                        'minor': 1
                    },
                    'authenticatorIndex': authenticatorIndex,
                    'requestType': 'Authenticate'
                }

                return window.navigator.fido.uafasm.processASMRequest(AuthenticationRequest)
                    .then((response) => {
                        assert.strictEqual(response.statusCode, ASM_STATUS_CODES_TO_INT.UAF_ASM_STATUS_ERROR, `ASM returned error code: ${ASM_STATUS_CODES[response.statusCode]}(${response.statusCode}). Expecting UAF_ASM_STATUS_ERROR(0x01)!`);
                    })
            })
        }
    })
})
