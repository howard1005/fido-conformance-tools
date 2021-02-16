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

        U2F-General-1

        Test authenticator processing meta information requests

    `, function() {



    let deviceInfo = undefined;
    before(() => {
        deviceInfo = getDeviceInfo();

        if (!deviceInfo)
            throw new Error('No U2F devices presented!')
    });

    this.timeout(10000);
    this.retries(3);

/* ---------- Positive Tests ---------- */

    it(`P-1

        Send a valid APDU GetVersion command, wait for the response and check that:
            (a) response status is SW_NO_ERROR
            (c) response data is equal to U2F_V2(2)

    `, () => {
        return sendValidCTAP_MSG(U2F_INS_VERSION)
            .then((result) => {
                assert.equal(APDU_STATUS_CODES.SW_NO_ERROR, result.statusCode, 'Authenticator returned an error: ' + hex.encode([result.statusCode]));
                assert.equal(result.responseStruct.version, 'U2F_V2', 'Authenticator must return "U2F_V2" on GetVersion command!');
            })
    })

/* ---------- Negative Tests ---------- */
   it(`F-1

        Send an APDU frame with an invalid INS, and check that response status code is SW_INS_NOT_SUPPORTED.

    `, () => {
        return sendCTAP_MSG(generateSecureRandomInt(45, 255), new Uint8Array(), {'fastSend': true})
            .catch((result) => {
                assert.equal(APDU_STATUS_CODES.SW_INS_NOT_SUPPORTED, result.statusCode, `Expected error code SW_INS_NOT_SUPPORTED. Received ${APDU_STATUS_CODES[result.statusCode]}`);
            })
    })

    it(`F-2

        Send an APDU frame with an invalid CLA, and check that response status code is SW_CLA_NOT_SUPPORTED.

    `, () => {
        return sendCTAP_MSG(U2F_INS_VERSION, new Uint8Array(), {'customCLA': generateSecureRandomInt(45, 255), 'fastSend': true})
            .catch((result) => {
                assert.equal(APDU_STATUS_CODES.SW_CLA_NOT_SUPPORTED, result.statusCode, `Expected error code SW_CLA_NOT_SUPPORTED. Received ${APDU_STATUS_CODES[result.statusCode]}`);
            })
    })

    it(`F-3

        Send an APDU GetVersion command with a random data buffer, and check that response status code is SW_WRONG_LENGTH. GetVersion does not take any input.

    `, () => {
        return sendCTAP_MSG(U2F_INS_VERSION, generateRandomBuffer(generateSecureRandomInt(1, 45)), {'fastSend': true})
            .catch((result) => {
                assert.equal(APDU_STATUS_CODES.SW_WRONG_LENGTH, result.statusCode, `Expected error code SW_WRONG_LENGTH. Received ${APDU_STATUS_CODES[result.statusCode]}`);
            })
    })
})