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

        Protocol-Reg-Resp-3

        Test the AuthenticatorRegistrationAssertion SEQUENCE

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

    let registrationRequest   = undefined;
    let registrationResponse  = undefined;
    let registrationAssertion = undefined;
    let assertionString       = undefined;
    let metadata              = undefined;

    before(function() {
        this.timeout(30000);

        metadata = window.config.test.metadataStatement;

        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((data) => {
                registrationRequest = data[0];
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }
                return authenticator.processUAFOperation(uafmessage)
            })
            .then((response) => {
                registrationResponse  = tryDecodeJSON(response.uafProtocolMessage)[0];
                registrationAssertion = registrationResponse.assertions[0];
                assertionString       = registrationAssertion.assertion;
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

/* ---------- Positive Tests ---------- */
    it(`P-1

        For each assertion in the assertions: Check that: 
            (a) "assertionScheme" field is of type DOMString and equal to "UAFV1TLV" 
            (b) "assertion" field is of type DOMString, base64URL encoded and less than 5460 characters(4096 bytes) long 
            (c) if "tcDisplayPNGCharacteristics" field is presented, it must be of type SEQUENCE, for each "DisplayPNGCharacteristicsDescriptor" member MUST be of type DICTIONARY, and: 
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
    `, () => {
        assert.strictEqual(registrationAssertion.assertionScheme, 'UAFV1TLV', 'assertionScheme MUST be UAFV1TLV!');
       
        assert.isString(registrationAssertion.assertion, 'Assertion MUST be of type DOMString!');
        assert.isBelow(registrationAssertion.assertion.length, 5460, 'Assertion MUST be shorter than 4096 bytes!');
        assert.match(registrationAssertion.assertion, /^[a-zA-Z0-9_-]+$/, 'Assertion MUST be base64URL(without padding) encoded!');

        if(registrationAssertion.tcDisplayPNGCharacteristics !== undefined) {
            assert.isArray(registrationAssertion.tcDisplayPNGCharacteristics, 'tcDisplayPNGCharacteristics MUST be a SEQUENCE!');
            
            for(let DisplayPNGCharacteristicsDescriptor of registrationAssertion.tcDisplayPNGCharacteristics) {
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

        if(registrationAssertion.exts !== undefined) {
            assert.isArray(registrationAssertion.exts, 'exts MUST be a SEQUENCE!');
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
            (b) TAG_UAFV1_REG_ASSERTION is a member of the TLV 
            (c) TAG_UAFV1_KRD is a member of the TAG_UAFV1_REG_ASSERTION 
            (d) TAG_AAID is a member of the TAG_UAFV1_KRD, must be nine(9) bytes long, and is decodes to the vendor AAID 
            (e) TAG_ASSERTION_INFO is a member of the TAG_UAFV1_KRD, is seven(7) bytes long and: 
                (1) "AuthenticatorVersion" must be equal to Metadata.authenticatorVersion 
                (2) "AuthenticationMode" must be 0x01 
                (3) "SignatureAlgAndEncoding" must be equal to Metadata.authenticationAlgorithm 
                (4) "PublicKeyAlgAndEncoding" must be equal to Metadata.publicKeyAlgAndEncoding 
            (f) TAG_FINAL_CHALLENGE_HASH is a member TAG_UAFV1_KRD, and is a SHA256 HASH of the FinalChallengeParams 
            (e) TAG_KEYID is a member of the TAG_UAFV1_KRD, and it is at least 32 bytes long 
            (f) TAG_COUNTERS is a member of the TAG_UAFV1_KRD, and it is eight(8) bytes long 
            (g) TAG_PUB_KEY is a member of the TAG_UAFV1_KRD
            (h) TAG_ATTESTATION_BASIC_FULL or TAG_ATTESTATION_BASIC_SURROGATE MUST be a member of TAG_UAFV1_REG_ASSERTION

    `, () => {
        
        let TLVBUFFER = base64url.decode(assertionString);
        let TAG_UAFV1_REG_ASSERTION_BUFFER = tlv.parser.searchTAG(TLVBUFFER, 'TAG_UAFV1_REG_ASSERTION');

        assert.strictEqual(TAG_UAFV1_REG_ASSERTION_BUFFER.bufferLength, TLVBUFFER.bufferLength, 'Buffer MUST not have any leftover bytes!')

        let TLVSTRUCT = tlv.parser.parse(TLVBUFFER);
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

        return crypto.subtle
            .digest('SHA-256', stringToArrayBuffer(registrationResponse.fcParams))
            .then((resultBuffer) => {
                let result = base64url.encode(resultBuffer)

                assert.strictEqual(result, TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_FINAL_CHALLENGE_HASH, `TAG_FINAL_CHALLENGE_HASH(${TAG_FINAL_CHALLENGE_HASH}) MUST equal to SHA256 hash of FinalChallengeParams(${result})`);
                
                if(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL === undefined
                && TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE === undefined) {
                    throw new Error('Neither TAG_ATTESTATION_BASIC_FULL nor TAG_ATTESTATION_BASIC_SURROGATE is presented!');
                }
            })
    })

    it(`P-3

        If TAG_UAFV1_REG_ASSERTION contains TAG_ATTESTATION_BASIC_FULL attestation: Decode "assertion" field base64url encoded TLV, and check that:
            (a) Check that TAG_ATTESTATION_BASIC_FULL is a member of Metadata.attestationTypes
            (b) TAG_ATTESTATION_BASIC_FULL is a member of the TAG_UAFV1_REG_ASSERTION 
            (c) TAG_SIGNATURE is a member of the TAG_ATTESTATION_BASIC_FULL 
            (d) TAG_ATTESTATION_CERT is a member of the TAG_ATTESTATION_BASIC_FULL
            (e) Collect all of the TAG_ATTESTATION_CERT members and create baseCertChain. For each attestationRoot in Metadata.attestationRootCertificates, prepend attestationRoot to the baseCertChain, and try verifying chain using the algorithm described in Section 6 of the RFC5280
            (d) TAG_SIGNATURE is a valid signature over TAG_UAFV1_KRD and can be verified using leaf certificate of the TAG_ATTESTATION_CERT

    `, () => {
        let TLVBUFFER    = base64url.decode(assertionString);
        let TLVSTRUCT    = tlv.parser.parse(TLVBUFFER);
        let TLVSTRUCTRAW = tlv.parser.parseButSkipValueDecoding(TLVBUFFER);

        if(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL !== undefined) {
            assert.include(metadata.attestationTypes, TAG_DIR_TO_INT.TAG_ATTESTATION_BASIC_FULL, 'TAG_ATTESTATION_BASIC_FULL attestation been presented, however it is NOT a member of attestationTypes given in metadata statement!');

            assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_SIGNATURE, 'TAG_ATTESTATION_BASIC_FULL missing TAG_UAFV1_KRD');
            assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_ATTESTATION_CERT, 'TAG_ATTESTATION_BASIC_FULL missing TAG_UAFV1_KRD');

            let baseCertChain = [];
            if(type(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_ATTESTATION_CERT) === 'Array')
                baseCertChain = TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_ATTESTATION_CERT;
            else
                baseCertChain = [TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_ATTESTATION_CERT];

            baseCertChain = baseCertChain.map((cert) => base64StringCertToPEM(base64.encode(base64url.decode(cert))));

            let chainIsValid = false;
            for(let attestationRootCertificate of metadata.attestationRootCertificates) {
                let certPem = base64StringCertToPEM(attestationRootCertificate)
                let validationChain = baseCertChain.concat([certPem]);
                chainIsValid = chainIsValid || verifyCertificateChain(validationChain)
            }
            assert.isTrue(chainIsValid, 'Can not validate certificate chain!');

            return verifyAssertion(assertionString)
                .then((valid) => {
                    assert.isTrue(valid, 'The signature is invalid!')
                })
        }
    })

    it(`P-4

        If TAG_UAFV1_REG_ASSERTION contains TAG_ATTESTATION_BASIC_SURROGATE attestation: Decode "assertion" field base64url encoded TLV, and check that:
            (a) Check that TAG_ATTESTATION_BASIC_SURROGATE is a member of Metadata.attestationTypes
            (b) TAG_ATTESTATION_BASIC_SURROGATE is a member of the TAG_UAFV1_REG_ASSERTION
            (c) TAG_SIGNATURE is a member of the TAG_ATTESTATION_BASIC_SURROGATE 
            (d) TAG_SIGNATURE is a valid signature over TAG_UAFV1_KRD and can be verified using TAG_PUB_KEY

    `, () => {
        let TLVBUFFER    = base64url.decode(assertionString);
        let TLVSTRUCT    = tlv.parser.parse(TLVBUFFER);
        let TLVSTRUCTRAW = tlv.parser.parseButSkipValueDecoding(TLVBUFFER);

        if(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE !== undefined) {
            assert.include(metadata.attestationTypes, TAG_DIR_TO_INT.TAG_ATTESTATION_BASIC_SURROGATE, 'TAG_ATTESTATION_BASIC_SURROGATE attestation been presented, however it is NOT a member of attestationTypes given in metadata statement!');
            assert.isDefined(TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE.TAG_SIGNATURE, 'TAG_ATTESTATION_BASIC_SURROGATE missing TAG_UAFV1_KRD');

            return verifyAssertion(assertionString)
                .then((valid) => {
                    assert.isTrue(valid, 'The signature is invalid!')
                })
        }
    })
})
