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

        HID-1

        Test U2F HID support

    `, function() {

    before(function(){
        this.timeout(10000)
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        if(getDeviceInfo().transport !== 'HID')
            this.skip();
    })

    this.timeout(30000);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Open CTAPHID device, and listen for incoming data for at least three seconds. Authenticator MUST not send any data in idle mode.

    `, () => {
        let response = window.navigator.fido.fido2.hid.readHIDResponseSync(getDeviceInfo(), 3000);

        assert.isEmpty(response, 'Received data while token was in idle.');
    })

    it(`P-2

        Send a random CONT frame to CTAPHID device, and listen for incoming data. Authenticator MUST NOT respond.

    `, () => {
        return new Promise((resolve, reject) => {
            let buffer = generateRandomBuffer(64);

            buffer[4] = 0;

            window.navigator.fido.fido2.hid.sendHIDBuffers(getDeviceInfo(), [buffer], 1000)
                .then((response) => {
                    reject(new Error('Received data while token was in idle.'))
                })
                .catch((error) => {
                    resolve()
                })
        })
    })

/* ----- INIT ----- */
    it(`P-3

        Send valid CTAPHID_INIT, on channel CTAPHID_BROADCAST_CID(0xffffffff), wait for the response and check that:
            (a) response.CID MUST equal to request.CID
            (b) response.CMD MUST equal to request.CMD
            (e) response.CTAPHID MUST equal to 2
            (f) response.DATA size MUST be 17
            (g) parse response.DATA and:
                (1) check that DATA.NONCE(+0) equal to request.NONCE
                (2) check that DATA.NEWCID(+8) MUST not be 0x00 nor equal to CTAPHID_BROADCAST_CID(0xffffffff)
                (3) check that DATA.CTAPHIDPROTOCOL(+12) MUST be set to CTAPHID_IF_VERSION(2)
                (4) check that in DATA.CAPABILITIES(+16) flags, only CAPABILITY_WINK(0x01), CAPABILITY_WINK(0x02), CAPABILITY_CBOR(0x04) or CAPABILITY_NMSG(0x08) set

    `, () => {
        let nonce = generateRandomBuffer(8);

        return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_INIT, nonce, CTAPHID_CIDO)
            .then((result) => {
                let response = parseCTAPHIDPacket(result);

                assert.equal(response.CMD, CTAPHID_CMD.CTAPHID_INIT, 'response.CMD MUST equal to request.CMD!');
                assert.deepEqual(response.CID, Array.from(CTAPHID_CIDO), 'response.CID MUST equal to request.CID!');
                assert.equal(response.BCNT, 17, 'response.DATA size MUST be 17!');
                assert.deepEqual(response.NONCE, Array.from(nonce), 'response.NONCE MUST equal to request.NONCE!');
                assert.notDeepEqual(response.NEWCID, [0x00, 0x00, 0x00, 0x00], 'response.NEWCID MUST be presented!');
                assert.equal(response.IFVERSION, CTAPHID_IF_VERSION, 'response.CTAPHID_VERSION MUST equal to CTAPHID_IF_VERSION(2)!');

                let flagsCopy = response.CAPABILITIES.raw;
                for(let flag of [CAPFLAG_WINK, CAPFLAG_LOCK, CAPFLAG_CBOR, CAPFLAG_NMSG]) {
                    if(!!(flagsCopy & flag))
                        flagsCopy = flagsCopy - flag;
                }
                assert.strictEqual(flagsCopy, 0, 'CAPABILITIES flags contains unsupported flags. Only WINK(0x01), LOCK(0x02), CBOR(0x04) or NMSG(0x08) allowed!');
            })
    })

    it(`P-4

        Send a three CTAPHID_INIT, on a CTAPHID_BROADCAST_CID(0xffffffff), wait for the responses and:
            (a) Recover CIDs from responses and check that they are unique.

    `, () => {
        let CIDs = [];

        let nonce = generateRandomBuffer(8);

        return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_INIT, nonce, CTAPHID_CIDO)
            .then((result) => {
                CIDs.push(cidToInt(new Uint8Array(parseCTAPHIDPacket(result).NEWCID)));

                let nonce = generateRandomBuffer(8);

                return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_INIT, nonce, CTAPHID_CIDO)
            })
            .then((result) => {
                CIDs.push(cidToInt(new Uint8Array(parseCTAPHIDPacket(result).NEWCID)));

                let nonce = generateRandomBuffer(8);

                return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_INIT, nonce, CTAPHID_CIDO)
            })
            .then((result) => {
                CIDs.push(cidToInt(new Uint8Array(parseCTAPHIDPacket(result).NEWCID)));

                assert.isNotTrue(CIDs[0] === CIDs[1] === CIDs[2], 'Authenticator must return unique new CID for every CTAPHID_INIT request!')
            })
    })
/* ----- INIT ENDS ----- */

/* ----- PING ----- */
    it(`P-5

        Send a single, valid CTAPHID_PING packet with a random payload, wait for the response, and check that response is equal to the request

    `, () => {
        return sendCTAPHID_INITCommand()
            .then((initResponse) => {
                let NEWCID  = initResponse.NEWCID;
                let payload = generateRandomBuffer(50);

                return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_PING, payload, NEWCID)
                    .then((result) => {
                        let response = parseCTAPHIDPacket(result);

                        assert.equal(CTAPHID_CMD.CTAPHID_PING, response.CMD);
                        assert.deepEqual(Array.from(payload), Array.from(response.DATA))
                        assert.equal(payload.length, response.BCNT);
                        assert.deepEqual(Array.from(NEWCID), Array.from(response.CID));
                    })
            })
    })


    it(`P-6

        Send a valid CTAPHID_PING, with a a large payload size(1024 bytes), and check that response is equal to the request

    `, () => {
        return sendCTAPHID_INITCommand()
            .then((initResponse) => {
                let NEWCID = initResponse.NEWCID;
                let payload = generateRandomBuffer(1024);

                return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_PING, payload, NEWCID)
                    .then((result) => {
                        let response = parseCTAPHIDPacket(result);

                        assert.equal(CTAPHID_CMD.CTAPHID_PING, response.CMD);
                        assert.deepEqual(Array.from(payload), Array.from(response.DATA))
                        assert.equal(payload.length, response.BCNT);
                        assert.deepEqual(Array.from(NEWCID), Array.from(response.CID));
                    })
            })
    })

    it(`P-7

        Send a valid CTAPHID_PING, with a a large payload size(512 bytes) that has last continuation frame missing, and send instead CTAPHID_INIT command on the same CID, check that it's succeeds(i.e. aborts CTAPHID_PING)

    `, () => {
        return sendCTAPHID_INITCommand()
            .then((initResponse) => {
                let NEWCID = initResponse.NEWCID;

                let payload = generateRandomBuffer(512);

                let pingFrames = generateHIDRequestFrames(CTAPHID_CMD.CTAPHID_PING, payload, NEWCID);
                pingFrames.pop(); // Removing last frame.

                let nonce = generateRandomBuffer(8)

                let initFrames = generateHIDRequestFrames(CTAPHID_CMD.CTAPHID_INIT, nonce, NEWCID); // Generating new CTAPHID_INIT frame
                pingFrames.push(initFrames[0]); // Pushing CTAPHID_INIT frame ontor pingFrames

                return window.navigator.fido.fido2.hid.sendHIDBuffers(getDeviceInfo(), pingFrames, 500)
                    .then((responseBuffers) => {
                        let responseBuffer = processResponseBuffers(responseBuffers);
                        let response       = parseCTAPHIDPacket(responseBuffer);

                        assert.equal(response.CMD, CTAPHID_CMD.CTAPHID_INIT, 'response.CMD MUST equal to request.CMD!');
                        assert.deepEqual(response.CID, Array.from(NEWCID), 'response.CID MUST equal to request.CID!');
                        assert.deepEqual(response.NONCE, Array.from(nonce), 'response.NONCE MUST equal to request.NONCE!');
                        assert.notDeepEqual(response.NEWCID, [0x00, 0x00, 0x00, 0x00], 'response.NEWCID MUST be presented!');
                        assert.equal(response.IFVERSION, CTAPHID_IF_VERSION, 'response.CTAPHID_VERSION MUST equal to CTAPHID_IF_VERSION(2)!');
                        assert.equal(response.BCNT, 17, 'response.DATA size MUST be 17!');
                    })
            })
    })

    it(`P-8

        Send a valid CTAPHID_PING, with data that contains a leding 0, and ensure that exact data is returned

    `, () => {
        let payload = generateRandomBuffer(58);

        payload[payload.length - 1] = 0;

        return sendCTAPHID_INITCommand()
        .then((initResponse) => {
            let NEWCID = initResponse.NEWCID;

            return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_PING, payload, NEWCID)
            .then((result) => {
                let response = parseCTAPHIDPacket(result);

                if (response.CMD === CTAPHID_CMD.CTAPHID_ERROR)
                    throw new Error(`Got an unexpecter error. Error message: ${response.ERRORMSG}`);

                assert.equal(CTAPHID_CMD.CTAPHID_PING, response.CMD);
                assert.deepEqual(Array.from(payload), Array.from(response.DATA))
                assert.equal(payload.length, response.BCNT);
                assert.deepEqual(Array.from(NEWCID), Array.from(response.CID));

                window.navigator.fido.fido2.hid.sendHIDCancel(getDeviceInfo(), NEWCID);
            })
        })
    })
/* ----- PING ENDS ----- */

/* ----- WINK -----*/
    it(`P-9

        If CTAPHID_WINK(0x08) is implemented, send CTAPHID_WINK(0x08), wait for the response, and:
            (a) response.CMD  is set to CTAPHID_WINK(0x08)
            (b) response.BCNT is set to 0
            (c) response length is 7 bytes

    `, function() {
        return sendCTAPHID_INITCommand()
        .then((initResponse) => {
            if (initResponse.CAPABILITIES.WINK) {
                return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_WINK, [], initResponse.NEWCID)
                    .then((result) => {
                        let response = parseCTAPHIDPacket(result);

                        if (response.CMD === CTAPHID_CMD.CTAPHID_ERROR)
                            throw new Error(`Got an unexpecter error. Error message: ${response.ERRORMSG}`);

                        assert.equal(CTAPHID_CMD.CTAPHID_WINK, response.CMD, `Expected Response.CMD to be CTAPHID_WINK(0x08). Got: ${CTAPHID_CMD[response.CMD]}(${'0x' + hex.encode([response.CMD])})`);
                        assert.equal(response.BCNT, 0, `Expected Response.BCNT to be 0. Got ${response.BCNT}`);
                    })
            } else
                this.skip()
        })
    })
/* ----- WINK ENDS ----- */

/* ---------- Negative Tests ---------- */
    it(`F-1

        Send an CTAPHID packet with an unknown command, and wait for the response:
            (a) response.CMD MUST be set to CTAPHID_ERROR
            (b) response.BCNT MUST equal to 1
            (c) response.ERRORCODE(DATA[0]) MUST be set to CTAP1_ERR_INVALID_COMMAND

    `, () => {
        return sendCTAPHID_INITCommand()
            .then((initResponse) => {
                return sendCTAPHIDCommand(0x80 | 0x21, [], initResponse.NEWCID) // Unknown command
                    .then((result) => {
                        let response = parseCTAPHIDPacket(result);

                        assert.equal(CTAPHID_CMD.CTAPHID_ERROR, response.CMD,
                            `Expected response.CMD to be CTAPHID_ERROR(0x3f). Got ${CTAPHID_CMD[response.CMD]}(${'0x' + hex.encode([response.CMD])})`);
                        assert.equal(1, response.BCNT, `Expected BCNT to be 1. Got ${response.BCNT}`);
                        assert.equal(CTAP_ERROR_CODES.CTAP1_ERR_INVALID_COMMAND, response.ERRORCODE, `Expected response error code to be (0x). Got ${CTAP_ERROR_CODES[response.ERRORCODE]}(${'0x' + hex.encode([response.ERRORCODE])})`);
                    })
            })
    })

    it(`F-2

        Send a valid CTAPHID_INIT packet, on a channel with id 0([0x00, 0x00, 0x00, 0x00]), and wait for the response:
            (a) response.CMD MUST be set to CTAPHID_ERROR
            (b) response.ERRORCODE(DATA[0]) MUST be set to CTAP1_ERR_INVALID_CHANNEL

    `, () => {
        let nonce = generateRandomBuffer(8);

        return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_INIT, nonce, [0x00, 0x00, 0x00, 0x00])
            .then((result) => {
                let response = parseCTAPHIDPacket(result);

                assert.equal(CTAPHID_CMD.CTAPHID_ERROR, response.CMD,
                    `Expected response.CMD to be CTAPHID_ERROR(0x3f). Got ${CTAPHID_CMD[response.CMD]}(${'0x' + hex.encode([response.CMD])})`);
                assert.equal(1, response.BCNT, `Expected BCNT to be 1. Got ${response.BCNT}`);
                assert.equal(CTAP_ERROR_CODES.CTAP1_ERR_INVALID_CHANNEL, response.ERRORCODE, `Expected response error code to be (0x). Got ${CTAP_ERROR_CODES[response.ERRORCODE]}(${'0x' + hex.encode([response.ERRORCODE])})`);
            })
    })

    it(`F-3

        Send a valid CTAPHID_PING packet, on a CID0 channel, and wait for the response:
            (a) response.CMD MUST be set to CTAPHID_ERROR
            (b) response.ERRORCODE(DATA[0]) MUST be set to CTAP1_ERR_INVALID_CHANNEL

    `, () => {
        let payload = generateRandomBuffer(32);

        return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_PING, payload, CTAPHID_CIDO)
            .then((result) => {
                let response = parseCTAPHIDPacket(result);

                assert.equal(CTAPHID_CMD.CTAPHID_ERROR, response.CMD,
                    `Expected response.CMD to be CTAPHID_ERROR(0x3f). Got ${CTAPHID_CMD[response.CMD]}(${'0x' + hex.encode([response.CMD])})`);
                assert.equal(1, response.BCNT, `Expected BCNT to be 1. Got ${response.BCNT}`);
                assert.equal(CTAP_ERROR_CODES.CTAP1_ERR_INVALID_CHANNEL, response.ERRORCODE, `Expected response error code to be (0x). Got ${CTAP_ERROR_CODES[response.ERRORCODE]}(${'0x' + hex.encode([response.ERRORCODE])})`);
            })
    })

    it(`F-4

        Send a valid CTAPHID_PING, with a a large payload size(1024 bytes), that has a continuation frame with a SEQ that is out of order and:
            (a) response.CMD MUST be set to CTAPHID_ERROR
            (b) response.ERRORCODE(DATA[0]) MUST be set to ERR_INVALID_SEQ(0x04)
    
    `, () => {
        return sendCTAPHID_INITCommand()
            .then((initResponse) => {
                let NEWCID = initResponse.NEWCID;

                let payload = generateRandomBuffer(1024);

                let pingFrames = generateHIDRequestFrames(CTAPHID_CMD.CTAPHID_PING, payload, NEWCID);

                pingFrames[pingFrames.length - 1].set([pingFrames[0][4] + 1], 4)
    
                return window.navigator.fido.fido2.hid.sendHIDBuffers(getDeviceInfo(), pingFrames)
                    .then((responseBuffers) => {
                        let responseBuffer = processResponseBuffers(responseBuffers);
                        let response       = parseCTAPHIDPacket(responseBuffer);

                        assert.equal(CTAPHID_CMD.CTAPHID_ERROR, response.CMD,
                            `Expected response.CMD to be CTAPHID_ERROR(0x3f). Got ${CTAPHID_CMD[response.CMD]}(${'0x' + hex.encode([response.CMD])})`);
                        assert.equal(1, response.BCNT, `Expected BCNT to be 1. Got ${response.BCNT}`);
                        assert.equal(CTAP_ERROR_CODES.CTAP1_ERR_INVALID_SEQ, response.ERRORCODE, `Expected response error code to be (0x). Got ${CTAP_ERROR_CODES[response.ERRORCODE]}(${'0x' + hex.encode([response.ERRORCODE])})`);
                    })
            })
    })
})
