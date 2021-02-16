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

        Protocol-Auth-Resp-3

        Test the AuthenticatorSignAssertion SEQUENCE

    `, function() {

    this.timeout(30000);
    this.retries(3);

    after(() => {
       return getTestStaticJSON(`Protocol-Dereg-Req-P`)
        .then((data) => {
            data[0].authenticators = [{'aaid': '', 'keyID': ''}]
            
            let uafmessage = {'uafProtocolMessage' : JSON.stringify(data)}

            return expectProcessUAFOperationSucceed(uafmessage);
        })
    })
    

    let userPublicKey           = undefined;
    let authenticationResponse  = undefined;
    let authenticationAssertion = undefined;
    before(function() {
        this.timeout(30000);
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((data) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data)
                }
                return authenticator.processUAFOperation(uafmessage)
            })
            .then((data) => {
                let registrationResponse = tryDecodeJSON(data.uafProtocolMessage)[0];
                userPublicKey = window.extractPublicKeysFromAssertion(registrationResponse.assertions[0].assertion).publicKey;
                return getTestStaticJSON('Protocol-Auth-Req-P')
            })
            .then((data) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data)
                }
                return authenticator.processUAFOperation(uafmessage)
            })
            .then((data) => {
                authenticationResponse  = tryDecodeJSON(data.uafProtocolMessage)[0];
                authenticationAssertion = authenticationResponse.assertions[0];
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    });
    let textPlainTransaction = {
        'contentType': 'text/plain',
        'content': stringToBase64URL('THIS IS TEST AND ITS COMPLETELY NOT FUNNY, SO PLEASE ACCEPT THE TRANSACTION!')
    }

    let getTcDisplayPNGCharacteristics = () => {
        if(window.config.test.metadataStatement.tcDisplayPNGCharacteristics)
            return window.config.test.metadataStatement.tcDisplayPNGCharacteristics[0]
    }
    let imagePNGTransaction = {
        'contentType': 'image/png',
        'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
        'tcDisplayPNGCharacteristics': getTcDisplayPNGCharacteristics()
    }

/* ---------- Positive Tests ---------- */
    it(`P-1

        For each assertion in the assertions: Check that: 
            (a) "assertionScheme" field is of type DOMString and equal to "UAFV1TLV" 
            (b) "assertion" field is of type DOMString, base64URL encoded and less than 5460 characters(4096 bytes) long 
            (c) if "exts" field is presented, it must be of type SEQUENCE

    `, () => {
        assert.strictEqual(authenticationAssertion.assertionScheme, 'UAFV1TLV', 'assertionScheme MUST be UAFV1TLV!');
       
        assert.isString(authenticationAssertion.assertion, 'Assertion MUST be of type DOMString!');
        assert.isBelow(authenticationAssertion.assertion.length, 5460, 'Assertion MUST be shorter than 4096 bytes!');
        assert.match(authenticationAssertion.assertion, /^[a-zA-Z0-9_-]+$/, 'Assertion MUST be base64URL(without padding) encoded!');

        if(authenticationAssertion.exts !== undefined) {
            assert.isArray(authenticationAssertion.exts, 'exts MUST be a SEQUENCE!');
        }
    })

    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    })

    it(`P-2

        Decode "assertion" field base64url encoded TLV, and check that: 
            (a) TLV does NOT have any leftover bytes 
            (b) TAG_UAFV1_AUTH_ASSERTION is a member of the TLV 
            (c) TAG_UAFV1_SIGNED_DATA is a member of the TAG_UAFV1_AUTH_ASSERTION 
            (d) TAG_AAID is a member of the TAG_UAFV1_SIGNED_DATA, must be nine(9) bytes long, and is decodes to the vendor AAID 
            (e) TAG_ASSERTION_INFO is a member of the TAG_UAFV1_SIGNED_DATA, is five(5) bytes long and: 
                (1) "AuthenticatorVersion" must be equal to Metadata.authenticatorVersion 
                (2) "AuthenticationMode" must be 0x01 
                (3) "SignatureAlgAndEncoding" must be equal to Metadata.authenticationAlgorithm 
            (f) TAG_AUTHENTICATOR_NONCE is a member of the TAG_UAFV1_SIGNED_DATA, and it is at least eight(8) bytes long 
            (g) TAG_FINAL_CHALLENGE_HASH is a member of the TAG_UAFV1_SIGNED_DATA, and is a SHA256 HASH of the FinalChallengeParams 
            (h) If authenticator is not able to display transaction content, i.e. metadataStatement.tcDisplay is set to 0x00003(ANY + PRIVILEGED_SOFTWARE) then: TAG_TRANSACTION_CONTENT_HASH is a member of the TAG_UAFV1_SIGNED_DATA, and is a SHA256 HASH of the "Transaction.content", and it's length is zero(0)
            (i) If authenticator is able to display transaction content, i.e. metadataStatement.tcDisplay is NOT set to 0x00003 then: TAG_TRANSACTION_CONTENT_HASH is a member of the TAG_UAFV1_SIGNED_DATA, and it's length is zero(0)
            (j) TAG_KEYID is a member of the TAG_UAFV1_SIGNED_DATA, and it is at least 32 bytes long 
            (k) TAG_COUNTERS is a member of the TAG_UAFV1_SIGNED_DATA, and it is four(4) bytes long 
            (l) TAG_SIGNATURE must be a member of TAG_UAFV1_AUTH_ASSERTION

    `, () => { 
        let TLVBUFFER = base64url.decode(authenticationAssertion.assertion);
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
            .digest('SHA-256', stringToArrayBuffer(authenticationResponse.fcParams))
            .then((resultBuffer) => {
                let result = base64url.encode(resultBuffer)

                assert.strictEqual(result, TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_FINAL_CHALLENGE_HASH, `TAG_FINAL_CHALLENGE_HASH(${TAG_FINAL_CHALLENGE_HASH}) MUST equal to SHA256 hash of FinalChallengeParams(${result})`);
                
                if(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE === undefined) {
                    throw new Error('TAG_SIGNATURE MUST be a member of TAG_UAFV1_AUTH_ASSERTION!');
                }
            })
    })

    it(`P-3

        Get AuthenticationResponse for AuthenticationRequest: Decode "assertion" field base64url encoded TLV, and check that: 
            (a) TAG_SIGNATURE is a member of the TAG_UAFV1_AUTH_ASSERTION 
            (b) If authenticator is not able to display transaction content, i.e. metadataStatement.tcDisplay is set to 0x00003(ANY + PRIVILEGED_SOFTWARE) then: TAG_TRANSACTION_CONTENT_HASH length is zero(0)
            (c) If authenticator is able to display transaction content, i.e. metadataStatement.tcDisplay is NOT set to 0x00003 then: TAG_TRANSACTION_CONTENT_HASH length is zero(0)
            (d) TAG_SIGNATURE is a valid signature over TAG_UAFV1_SIGNED_DATA and can be verified using PublicKey saved from the registration.

    `, () => {
        let TLVBUFFER    = base64url.decode(authenticationAssertion.assertion);
        let TLVSTRUCT    = tlv.parser.parse(TLVBUFFER);
        let TLVSTRUCTRAW = tlv.parser.parseButSkipValueDecoding(TLVBUFFER);

        assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH, 'TAG_UAFV1_SIGNED_DATA missing TAG_TRANSACTION_CONTENT_HASH');
        assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH.byteLength, 0, 'TAG_TRANSACTION_CONTENT_HASH MUST zero(0) bytes long!');

        return verifyAssertion(authenticationAssertion.assertion, userPublicKey)
            .then((valid) => {
                assert.isTrue(valid, 'The signature is invalid!')
            })
    })

    it(`P-4

        Get AuthenticationResponse for AuthenticationRequest with provided Transaction: Decode "assertion" field base64url encoded TLV, and check that: 
            (a) TAG_SIGNATURE is a member of the TAG_UAFV1_AUTH_ASSERTION 
            (b) If authenticator is not able to display transaction content, i.e. metadataStatement.tcDisplay is set to 0x00003(ANY + PRIVILEGED_SOFTWARE) then: TAG_TRANSACTION_CONTENT_HASH is a member of the TAG_UAFV1_SIGNED_DATA, and is a SHA256 HASH of the "Transaction.content", and it's length is 32
            (c) If authenticator is able to display transaction content, i.e. metadataStatement.tcDisplay is NOT set to 0x00003 then: TAG_TRANSACTION_CONTENT_HASH is a member of the TAG_UAFV1_SIGNED_DATA, and it's length MUST equal to the length of the Transaction.content
            (d) TAG_SIGNATURE is a valid signature over TAG_UAFV1_SIGNED_DATA and can be verified using PublicKey saved from the registration.

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0) {
            let selectedTransaction = undefined;
            if(window.config.test.metadataStatement.tcDisplayContentType === 'text/plain') {
                selectedTransaction = textPlainTransaction;
            } else if(window.config.test.metadataStatement.tcDisplayContentType === 'image/png') {
                selectedTransaction = imagePNGTransaction;
            }

            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    data[0].transaction = [selectedTransaction];

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data)
                    }
                    return authenticator.processUAFOperation(uafmessage)
                })
                .then((data) => {
                    assertion = tryDecodeJSON(data.uafProtocolMessage)[0].assertions[0].assertion;

                    let TLVBUFFER    = base64url.decode(assertion);
                    let TLVSTRUCT    = tlv.parser.parse(TLVBUFFER);
                    let TLVSTRUCTRAW = tlv.parser.parseButSkipValueDecoding(TLVBUFFER);

                    let promises = [];

                    assert.isDefined(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH, 'TAG_UAFV1_SIGNED_DATA missing TAG_TRANSACTION_CONTENT_HASH');
                    assert.strictEqual(TLVSTRUCTRAW.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH.byteLength, 32, 'TAG_TRANSACTION_CONTENT_HASH MUST be exactly 32 bytes long!');

                    let tcHashPromise = crypto.subtle
                        .digest('SHA-256', base64url.decode(selectedTransaction.content))
                        .then((resultBuffer) => {
                            let result = base64url.encode(resultBuffer);

                            assert.strictEqual(TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH, result, `TAG_TRANSACTION_CONTENT_HASH(${TLVSTRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_TRANSACTION_CONTENT_HASH}) does not equal to the hash of given transaction(${result})!`)
                        })

                    promises.push(tcHashPromise);

                    let verifyAssertionPromise = verifyAssertion(assertion, userPublicKey)
                        .then((valid) => {
                            assert.isTrue(valid, 'The signature is invalid!')
                        })
                    promises.push(verifyAssertionPromise);

                    return Promise.all(promises)
                })
        }
    })
})
