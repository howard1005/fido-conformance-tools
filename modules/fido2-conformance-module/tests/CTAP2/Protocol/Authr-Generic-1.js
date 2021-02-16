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

        Authr-Generic-1

        Generic FIDO protocol tests

    `, function() {

    let metadata                   = window.config.test.metadataStatement
    let getInfo_response           = undefined;

    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return sendCTAP_CBOR(generateGetInfoRequest())
            .then((response) => {
                getInfo_response = response.cborResponse
            })
    })

    this.timeout(5000);
    this.retries(3);
    
    it(`P-1

        Send a valid CTAP2 GetInfo request, wait for the response and check that:
            (a) CTAP2 responseCode is CTAP1_ERR_SUCCESS(0x00)
            (b) Check that version(0x01) field is presented and is set to "FIDO_2_0"
            (c) Check that aaguid(0x03) field is presented and is 16 bytes long
            (d) If GetInfo contains extensions(0x03) field, check that its of type SEQUENCE, and only contains STRINGS
            (e) If GetInfo contains options(0x04) field, check that its of type MAP
            (f) If GetInfo contains maxMsgSize(0x05) field, check that its of type NUMBER
            (g) If GetInfo contains pinProtocols(0x06) field, check that its of type SEQUENCE, and only contains NUMBERS

    `, () => {
        assert.isDefined(getInfo_response[GetInfoRespKeys.versions], 'GetInfo response is missing version(0x01) field!');
        assert.isArray(getInfo_response[GetInfoRespKeys.versions], 'version MUST be of type ARRAY!');
        assert.include(getInfo_response[GetInfoRespKeys.versions], 'FIDO_2_0', 'GetInfo.versions MUST contain "FIDO_2_0"!');

        assert.isDefined(getInfo_response[GetInfoRespKeys.aaguid], 'GetInfo response is missing aaguid(0x03) field!');
        assert.strictEqual(getInfo_response[GetInfoRespKeys.aaguid], metadata.aaguid.replace(/-/g, ''), 'GetInfo.aaguid MUST strictly equal to aaguid in metadata statement!');

        if(getInfo_response[GetInfoRespKeys.extensions]) {
            assert.isArray(getInfo_response[GetInfoRespKeys.extensions], 'GetInfo.extensions MUST be of type SEQUENCE');
            for(let extId of getInfo_response[GetInfoRespKeys.extensions])
                assert.isString(extId, 'Extension ids MUST be of type STRING!');
        }

        if(getInfo_response[GetInfoRespKeys.options]) {
            assert.isObject(getInfo_response[GetInfoRespKeys.options], 'GetInfo.options MUST be of type MAP');
        }

        if(getInfo_response[GetInfoRespKeys.maxMsgSize]) {
            assert.isNumber(getInfo_response[GetInfoRespKeys.maxMsgSize], 'GetInfo.maxMsgSize MUST be of type NUMBER!');
        }

        if(getInfo_response[GetInfoRespKeys.pinProtocols]) {
            assert.isArray(getInfo_response[GetInfoRespKeys.pinProtocols], 'GetInfo.pinProtocols MUST be of type SEQUENCE');
            for(let protocolVersion of getInfo_response[GetInfoRespKeys.pinProtocols])
                assert.isNumber(protocolVersion, 'GetInfo.pinProtocols MUST only contain numeric protocol identifiers!');
        }
    })

    it(`P-2

        If GetInfo contains Options field: Check that every option in options is of type Boolean. Additionally:
            (a) If "up" is set to true, check that metadata.userVerificationDetails contains VerificationMethodDescriptor that has "userVerification" set to USER_VERIFY_PRESENCE
            (b) If "uv" is set to true, check that metadata.userVerificationDetails contains VerificationMethodDescriptor that has "userVerification" set to either of USER_VERIFY_PASSCODE/FINGERPRINT/VOICEPRINT/FACEPRINT/EYEPRINT/HANDPRINT/PATTERN
            (c) If "uv" and "up" are false, check that metadata.userVerificationDetails contains VerificationMethodDescriptor that has "userVerification" set to USER_VERIFY_NONE

    `, () => {
        let options = getInfo_response[GetInfoRespKeys.options];

        if(!options || options.up === undefined || options.up === true) {
            assert.isTrue(metadataUserVerificationDetailsContainsAnyOf([USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_PRESENCE]), 'Metadata statement missing VerificationMethodDescriptor for test of user presence!');
        }

        if(options) {
            assert.isObject(options, 'GetInfo.options MUST be of type MAP');

            for(let key in options) {
                assert.isBoolean(options[key], `Options.${key} value MUST be of type Boolean!`);
            }

            if(options.uv) {
                assert.isTrue(metadataUserVerificationDetailsContainsAnyOf([
                    USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_PASSCODE,
                    USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_FINGERPRINT,
                    USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_VOICEPRINT,
                    USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_FACEPRINT,
                    USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_EYEPRINT,
                    USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_HANDPRINT,
                    USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_PATTERN
                    ]), 'Metadata statement missing VerificationMethodDescriptor for user verification!');
            }

            if(!(options || options.up === undefined || options.up === true) && !options.uv) {
                assert.isTrue(metadataUserVerificationDetailsContainsAnyOf([USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_NONE]), 'For authenticator that does not support TUP , metadata statement userVerification must contain USER_VERIFY_NONE!!');
            }
        }
    })

    it(`P-3

        If GetInfo contains PinProtocols, and it is not empty, check that Metadata.userVerificationDetails contains VerificationMethodDescriptor set to USER_VERIFY_PASSCODE

    `, () => {
        let pinProtocols = getInfo_response[GetInfoRespKeys.pinProtocols];

        if(pinProtocols && pinProtocols.length > 0) {
            assert.isTrue(metadataUserVerificationDetailsContainsAnyOf([USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_PASSCODE]), 'For authenticator that support ClientPin, Metadata statement missing VerificationMethodDescriptor for USER_VERIFY_PASSCODE!');
        }
    })
})
