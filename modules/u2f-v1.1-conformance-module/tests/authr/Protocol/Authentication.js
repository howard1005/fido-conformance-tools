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

        U2F-Authenticate-1

        Test U2FHID_MSG command and APDU processing

    `, function() {



    let deviceInfo = undefined;
    before(() => {
        deviceInfo = window.config.test.fidoauthenticator;

        if (!deviceInfo)
            throw new Error('No U2F devices presented!')
    });

    this.timeout(10000);
    // this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Send a valid APDU Register command, wait for response, and:
            (a) parse response data and preserve public-key and keyHandle
            (b) send a valid APDU Signature command, with a control byte set to "enforce-user-presence-and-sign"(0x03), and with previously preserved keyHandle
            (c) wait for the response
            (a) check that signResponse status is SW_NO_ERROR
            (b) parse signResponse data and:
                (i)   check that UP flag is set
                (ii)  extract signature
                (iii) construct original challenge data, and verify signature using previously preserved public-key

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {                
                assert.equal(0x05, result.responseStruct.RESERVE, 'Reserve byte MUST be set to 0x05!');
                assert.isTrue(verifyRegistrationResponse(challengeHash, appIDHash, result.responseStruct), 'Failed to verify Registration signature!');

                /* ---- GENERATE AURTHENTICATION REQUEST ---- */
                let PUBKEY    = result.responseStruct.PUBKEY;
                let KEYHANDLE = result.responseStruct.KEYHANDLE;

                let challengeSignHash = generateRandomBuffer(32);

                let payload = generateAPDUSignFrame(challengeSignHash, appIDHash, KEYHANDLE);
                return sendValidCTAP_MSG(U2F_INS_AUTHENTICATE, payload, {'enforceUP': true})
                    .then((result) => {
                        assert.isTrue(result.responseStruct.UP, 'Expected Authenticator to enforce User Presence!');
                        assert.isTrue(verifySignResponse(challengeSignHash, appIDHash, PUBKEY, result.responseStruct), 'Failed to verify Sign assertion!');
                    })
            })
    })


    it(`P-2

        Send two valid APDU Signature command, with a control byte set to "enforce-user-presence-and-sign"(0x03), wait for the responses and check that response2.counter is bigger than response1.counter

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {                
                assert.equal(0x05, result.responseStruct.RESERVE, 'Reserve byte MUST be set to 0x05!');
                assert.isTrue(verifyRegistrationResponse(challengeHash, appIDHash, result.responseStruct), 'Failed to verify Registration signature!');

                /* ---- GENERATE AURTHENTICATION REQUEST ---- */
                let PUBKEY    = result.responseStruct.PUBKEY;
                let KEYHANDLE = result.responseStruct.KEYHANDLE;
                let counter1  = undefined;
                let counter2  = undefined;

                let challengeSignHash1 = generateRandomBuffer(32);
                let challengeSignHash2 = generateRandomBuffer(32);

                let payload = generateAPDUSignFrame(challengeSignHash1, appIDHash, KEYHANDLE);
                return sendValidCTAP_MSG(U2F_INS_AUTHENTICATE, payload, {'enforceUP': true})
                    .then((result) => {
                        assert.isTrue(result.responseStruct.UP, 'Expected Authenticator to enforce User Presence!');
                        assert.isTrue(verifySignResponse(challengeSignHash1, appIDHash, PUBKEY, result.responseStruct), 'Failed to verify Sign assertion!');

                        counter1 = result.responseStruct.COUNTER;

                        let payload = generateAPDUSignFrame(challengeSignHash2, appIDHash, KEYHANDLE);
                        return sendValidCTAP_MSG(U2F_INS_AUTHENTICATE, payload, {'enforceUP': true})
                    })
                   .then((result) => {
                        assert.isTrue(result.responseStruct.UP, 'Expected Authenticator to enforce User Presence!');
                        assert.isTrue(verifySignResponse(challengeSignHash2, appIDHash, PUBKEY, result.responseStruct), 'Failed to verify Sign assertion!');

                       counter2 = result.responseStruct.COUNTER;
                    })
                    .then(() => {
                        assert.isAbove(counter2, counter1, 'Expected counter from request 2 to be larger than counter from request 1!');
                    })
            })
    })

    it(`P-3

        Send a valid APDU Signature command, with a control byte set to "check-only"(0x07), and correct keyHandle, wait for the response and check that:
            (a) response status is SW_NO_ERROR
            (b) response data MUST be empty

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {                
                assert.equal(0x05, result.responseStruct.RESERVE, 'Reserve byte MUST be set to 0x05!');
                assert.isTrue(verifyRegistrationResponse(challengeHash, appIDHash, result.responseStruct), 'Failed to verify Registration signature!');

                /* ---- GENERATE AURTHENTICATION REQUEST ---- */
                let PUBKEY    = result.responseStruct.PUBKEY;
                let KEYHANDLE = result.responseStruct.KEYHANDLE;

                let challengeSignHash = generateRandomBuffer(32);

                let payload = generateAPDUSignFrame(challengeSignHash, appIDHash, KEYHANDLE);
                return sendCTAP_MSG(U2F_INS_AUTHENTICATE, payload, {'checkOnly': true, 'fastSend': true})
                    .then((result) => {
                        assert.equal(APDU_STATUS_CODES.SW_CONDITIONS_NOT_SATISFIED, result.statusCode, 'For Sign with CheckOnly, for an existing credential, authenticator must return SW_CONDITIONS_NOT_SATISFIED(0x6985)! Authenticator returned: ' + APDU_STATUS_CODES[result.statusCode]);

                        assert.isUndefined(result.responseStruct, 'Authenticator returned data for checkOnly!');
                    })
            })
    })

/* ---------- Negative Tests ---------- */
    it(`F-1

        Send an APDU Authenticate command with a data buffer that is missing keyHandle(so 66 bytes long), wait for the respone, and check that response status code is SW_WRONG_DATA.

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {                
                assert.equal(0x05, result.responseStruct.RESERVE, 'Reserve byte MUST be set to 0x05!');
                assert.isTrue(verifyRegistrationResponse(challengeHash, appIDHash, result.responseStruct), 'Failed to verify Registration signature!');

                /* ---- GENERATE AURTHENTICATION REQUEST ---- */
                let PUBKEY    = result.responseStruct.PUBKEY;
                let KEYHANDLE = new Uint8Array();

                let challengeSignHash = generateRandomBuffer(32);

                let payload = generateAPDUSignFrame(challengeSignHash, appIDHash, KEYHANDLE);
                return sendCTAP_MSG(U2F_INS_AUTHENTICATE, payload, {'checkOnly': true, 'fastSend': true})
                    .then((result) => {
                        assert.equal(APDU_STATUS_CODES.SW_WRONG_DATA, result.statusCode, 'Expected SW_WRONG_DATA! Got: ' + APDU_STATUS_CODES[result.statusCode]);
                    })
            })
    })

    it(`F-2

        Send an APDU Authenticate command, with non-existing AppID, wait for the response, and check that response status code is SW_WRONG_DATA

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {                
                assert.equal(0x05, result.responseStruct.RESERVE, 'Reserve byte MUST be set to 0x05!');
                assert.isTrue(verifyRegistrationResponse(challengeHash, appIDHash, result.responseStruct), 'Failed to verify Registration signature!');

                /* ---- GENERATE AURTHENTICATION REQUEST ---- */
                let PUBKEY    = result.responseStruct.PUBKEY;
                let KEYHANDLE = result.responseStruct.KEYHANDLE;
                appIDHash = generateRandomBuffer(32);

                let challengeSignHash = generateRandomBuffer(32);

                let payload = generateAPDUSignFrame(challengeSignHash, appIDHash, KEYHANDLE);
                return sendCTAP_MSG(U2F_INS_AUTHENTICATE, payload, {'checkOnly': true, 'fastSend': true})
                    .then((result) => {
                        assert.equal(APDU_STATUS_CODES.SW_WRONG_DATA, result.statusCode, 'Expected SW_WRONG_DATA! Got: ' + APDU_STATUS_CODES[result.statusCode]);
                    })
            })
    })


    it(`F-3

        Send an APDU Authenticate command, with non-existing keyHandle, wait for the response, and check that response status code is SW_WRONG_DATA.

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {                
                assert.equal(0x05, result.responseStruct.RESERVE, 'Reserve byte MUST be set to 0x05!');
                assert.isTrue(verifyRegistrationResponse(challengeHash, appIDHash, result.responseStruct), 'Failed to verify Registration signature!');

                /* ---- GENERATE AURTHENTICATION REQUEST ---- */
                let PUBKEY    = result.responseStruct.PUBKEY;
                let KEYHANDLE = generateRandomBuffer(64);

                let challengeSignHash = generateRandomBuffer(32);

                let payload = generateAPDUSignFrame(challengeSignHash, appIDHash, KEYHANDLE);
                return sendCTAP_MSG(U2F_INS_AUTHENTICATE, payload, {'checkOnly': true, 'fastSend': true})
                    .catch((result) => {
                        assert.equal(APDU_STATUS_CODES.SW_WRONG_DATA, result.statusCode, 'Expected SW_WRONG_DATA! Got: ' + APDU_STATUS_CODES[result.statusCode]);
                    })
            })
    })


    it(`F-4

        Send a valid APDU Signature command, with a control byte set to "check-only"(0x07), and unknown keyHandle, wait for the response and check that:
            (a) response status is SW_WRONG_DATA
            (b) response data MUST be empty

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {                
                assert.equal(0x05, result.responseStruct.RESERVE, 'Reserve byte MUST be set to 0x05!');
                assert.isTrue(verifyRegistrationResponse(challengeHash, appIDHash, result.responseStruct), 'Failed to verify Registration signature!');

                /* ---- GENERATE AURTHENTICATION REQUEST ---- */
                let PUBKEY    = result.responseStruct.PUBKEY;
                let KEYHANDLE = generateRandomBuffer(64);

                let challengeSignHash = generateRandomBuffer(32);

                let payload = generateAPDUSignFrame(challengeSignHash, appIDHash, KEYHANDLE);
                return sendCTAP_MSG(U2F_INS_AUTHENTICATE, payload, {'checkOnly': true, 'fastSend': true})
                    .then((result) => {
                        assert.equal(APDU_STATUS_CODES.SW_WRONG_DATA, result.statusCode, 'For Sign with CheckOnly, for an existing credential, authenticator must return SW_WRONG_DATA(0x6985)! Authenticator returned: ' + APDU_STATUS_CODES[result.statusCode]);

                        assert.isUndefined(result.responseStruct, 'Authenticator returned data for checkOnly!');
                    })
            })
    })
})
