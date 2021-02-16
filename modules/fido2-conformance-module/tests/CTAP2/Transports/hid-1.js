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

        Test CTAP2 HID support

    `, function() {

    let deviceInfo              = undefined;
    let CTAPHID_MAX_PACKET_SIZE = undefined;

    before(function(){
        this.timeout(10000)
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        deviceInfo = getDeviceInfo();

        if(getDeviceInfo().transport !== 'HID')
            this.skip();

        if(window.config && window.config.test && window.config.test.CustomHIDConfigSize) {
            CTAPHID_MAX_PACKET_SIZE = window.config.test.CustomHIDConfigSize;
            console.error("!!!! WARNING! CUSTOME HID PACKET SIZE ENABLED !!!!");
        }

        return sendReset()
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
            let buffer = generateRandomBuffer(CTAPHID_MAX_PACKET_SIZE);
            window.crypto.getRandomValues(buffer); 

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
                (5) check that in DATA.CAPABILITIES(+16) flags that CAPABILITY_CBOR(0x04) is set

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

                assert.isTrue(response.CAPABILITIES.CBOR, 'CAPABILITIES flags MUST have CBOR(0x08) set!');
            })
    })

    it(`P-4

        Send a three CTAPHID_INIT, on a CTAPHID_BROADCAST_CID(0xffffffff), wait for the responses and:
            (a) Recover CIDs from responses and check that they are unique.

    `, () => {
        let CIDs = [];

        let nonce = generateRandomBuffer(8);
        window.crypto.getRandomValues(nonce);

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

                let pingFrames = generateRequestFrames(CTAPHID_CMD.CTAPHID_PING, payload, NEWCID);
                pingFrames.pop(); // Removing last frame.

                let nonce = generateRandomBuffer(8)
                let initFrames = generateRequestFrames(CTAPHID_CMD.CTAPHID_INIT, nonce, NEWCID); // Generating new CTAPHID_INIT frame
                pingFrames.push(initFrames[0]); // Pushing CTAPHID_INIT frame ontor pingFrames

                return window.navigator.fido.fido2.hid.sendHIDBuffers(getDeviceInfo(), pingFrames)
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

/* ----- KEEPALIVE ----- */
    it(`P-9

        Send a valid MakeCredential request, and while its waiting for user action check that authenticator returns CTAPHID_KEEPALIVE(0x3B), that is 8 byte long, BCNT is 1 and DATA is either STATUS_PROCESSING(0x01) or STATUS_UPNEEDED(0x02)

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAPHID_INITCommand()
        .then((initResponse) => {
            let NEWCID  = initResponse.NEWCID;

            alert('!!!DO NOT PERFORM TEST OF USER PRESENCE!!!');

            let buffers = generateRequestFrames(CTAPHID_CMD.CTAPHID_CBOR, commandBuffer, NEWCID);
            window.navigator.fido.fido2.hid.sendHIDBuffersSync(getDeviceInfo(), buffers);
            
            return TimeoutPromise(100)
            .then(() => {
                let keepAliveResponseFrame = window.navigator.fido.fido2.hid.readHIDResponseSync(getDeviceInfo(), 700);
                let keepAliveResponse      = parseCTAPHIDPacket(keepAliveResponseFrame)

                assert.strictEqual(keepAliveResponse.CMD, CTAPHID_CMD.CTAPHID_KEEPALIVE, 'Response.CMD MUST be set to CTAPHID_KEEPALIVE(0x3B)!')
                assert.include([STATUS_PROCESSING, STATUS_UPNEEDED], keepAliveResponse.STATUSCODE, 'KEEPALIVE status code MUST be either STATUS_PROCESSING(0x01) or STATUS_UPNEEDED(0x02)');

                return TimeoutPromise(200)
            })
            .then(() => window.navigator.fido.fido2.hid.sendHIDCancel(getDeviceInfo(), NEWCID))
            .then(() => TimeoutPromise(200))

        })
    })
/* ----- KEEPALIVE ENDS ----- */

/* ----- KEEPALIVE ----- */
    it(`P-10

        Send a valid MakeCredential request, and check that authenticator returns CTAPHID_KEEPALIVE(0x3B) while its waiting for user action.
        Send CTAPHID_CANCEL(0x11) and check that authenticator responds with CTAPHID_CBOR(0x90) with error code CTAP2_ERR_KEEPALIVE_CANCEL(0x2D).
        Send another CTAPHID_CANCEL(0x11) and check that authenticator does not respond with anything

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams)

        return sendCTAPHID_INITCommand()
        .then((initResponse) => {
            let NEWCID = initResponse.NEWCID;
            let makeCredsBuffers = generateRequestFrames(CTAPHID_CMD.CTAPHID_CBOR, commandBuffer, NEWCID);

            window.navigator.fido.fido2.hid.sendHIDBuffersSync(getDeviceInfo(), makeCredsBuffers);
            let responseFrame = [];
            return TimeoutPromise(250)
            .then(() => {
                let keepAliveResponseFrame = window.navigator.fido.fido2.hid.readHIDResponseSync(getDeviceInfo(), 500);
                let keepAliveResponse      = parseCTAPHIDPacket(keepAliveResponseFrame);

                assert.strictEqual(keepAliveResponse.CMD, CTAPHID_CMD.CTAPHID_KEEPALIVE, `Expected CTAPHID_KEEPALIVE(0x3B). Got: ${CTAPHID_CMD[keepAliveResponse.CMD]}(${'0x' + hex.encode([keepAliveResponse.CMD])})`)
                assert.include([STATUS_PROCESSING, STATUS_UPNEEDED], keepAliveResponse.STATUSCODE, 'KEEPALIVE status code MUST be either STATUS_PROCESSING(0x01) or STATUS_UPNEEDED(0x02)');
            
                let cancelResponseFrame = window.navigator.fido.fido2.hid.sendHIDCancel(getDeviceInfo(), NEWCID)
                assert.strictEqual(cancelResponseFrame[4], CTAPHID_CMD.CTAPHID_CBOR, `Expected CTAPHID_CBOR(0x90). Got: ${CTAPHID_CMD[cancelResponseFrame[4]]}(${'0x' + hex.encode([cancelResponseFrame[4]])})`)

                assert.strictEqual(cancelResponseFrame[7], CTAP_ERROR_CODES.CTAP2_ERR_KEEPALIVE_CANCEL, `The response to CTAPHID_CANCEL response while authenticator polling CTAPHID_KEEPALIVE MUST be CTAPHID_CBOR with error code CTAP2_ERR_KEEPALIVE_CANCEL! Expected CTAPHID_CBOR. Got ${CTAPHID_CMD[cancelResponseFrame[7]]}(${cancelResponseFrame[7]})`);
            })
            .then(() => {
                let cancelResponseFrame = navigator.fido.fido2.hid.sendHIDCancel(getDeviceInfo(), NEWCID);
                
                assert.strictEqual(cancelResponseFrame.length, 0, 'Authenticator responded to CTAPHID_CANCEL!');
             })
        })
    })

    it(`P-11

        Send a valid GetAssertion request with invalid credId. Check that authenticator frist returns CTAPHID_KEEPALIVE(0x3B). Then waiting till authr finally returns CTAP2_ERR_NO_CREDENTIALS(0x2E)

    `, () => {
        let allowList = [{
            type: 'public-key', id: generateRandomBuffer(32)
        }]

        let rpId = generateRandomDomain();
        let goodAssertion      = generateGoodCTAP2GetAssertion(`https://${rpId}`);
        let getAssertionBuffer = generateGetAssertionReqCBOR(rpId, goodAssertion.clientDataHash, allowList)

        return sendCTAPHID_INITCommand()
        .then((initResponse) => {
            let NEWCID = initResponse.NEWCID;
            let hidReqBuffers = generateRequestFrames(CTAPHID_CMD.CTAPHID_CBOR, getAssertionBuffer, NEWCID);

            window.navigator.fido.fido2.hid.sendHIDBuffersSync(getDeviceInfo(), hidReqBuffers);
            let responseFrame = [];
            return TimeoutPromise(250)
            .then(() => {
                let keepAliveResponseFrame = window.navigator.fido.fido2.hid.readHIDResponseSync(getDeviceInfo(), 500);
                let keepAliveResponse      = parseCTAPHIDPacket(keepAliveResponseFrame);

                assert.strictEqual(keepAliveResponse.CMD, CTAPHID_CMD.CTAPHID_KEEPALIVE, `Expected CTAPHID_KEEPALIVE(0x3B). Got: ${CTAPHID_CMD[keepAliveResponse.CMD]}(${'0x' + hex.encode([keepAliveResponse.CMD])})`)
                assert.include([STATUS_UPNEEDED], keepAliveResponse.STATUSCODE, 'KEEPALIVE status code MUST be either STATUS_UPNEEDED(0x02)');
            
                let cancelResponseFrame = window.navigator.fido.fido2.hid.sendHIDCancel(getDeviceInfo(), NEWCID)
                assert.strictEqual(cancelResponseFrame[4], CTAPHID_CMD.CTAPHID_CBOR, `Expected CTAPHID_CBOR(0x90). Got: ${CTAPHID_CMD[cancelResponseFrame[4]]}(${'0x' + hex.encode([cancelResponseFrame[4]])})`)

                assert.strictEqual(cancelResponseFrame[7], CTAP_ERROR_CODES.CTAP2_ERR_KEEPALIVE_CANCEL, `The response to CTAPHID_CANCEL response while authenticator polling CTAPHID_KEEPALIVE MUST be CTAPHID_CBOR with error code CTAP2_ERR_KEEPALIVE_CANCEL! Expected CTAPHID_CBOR. Got ${CTAPHID_CMD[cancelResponseFrame[7]]}(${cancelResponseFrame[7]})`);
            })
        })
    })
/* ----- KEEPALIVE ENDS ----- */

/* ----- WINK -----*/
    it(`P-12

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

/* ----- LOCK ----- */
    it(`P-13

        If CTAPHID_LOCK(0x04) is implemented, send a valid CTAPHID_LOCK(0x04), with lock time set to 0, wait for the response, and check that:
            (a) response.CID MUST equal to request.CID
            (b) response.CMD MUST equal to request.CMD
            (c) response.BCNT MUST equal to 0
            (d) response length must be 7 bytes

    `, function() {
        return sendCTAPHID_INITCommand()
            .then((initResponse) => {
                if (initResponse.CAPABILITIES.LOCK) { 
                    return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_LOCK, [0], initResponse.NEWCID)
                        .then((result) => {
                            let response = parseCTAPHIDPacket(result);

                            if (response.CMD === CTAPHID_CMD.CTAPHID_ERROR)
                                throw new Error(`Got an unexpecter error. Error message: ${response.ERRORMSG}`);

                            assert.equal(CTAPHID_CMD.CTAPHID_LOCK, response.CMD,
                                `Expected Response.CMD to be CTAPHID_LOCK(0x04). Got: ${CTAPHID_CMD[response.CMD]}(${'0x' + hex.encode([response.CMD])})`);
                            assert.deepEqual(Array.from(initResponse.NEWCID), Array.from(response.CID), `Expected request CID to be ${hex.encode(initResponse.NEWCID)}. Got ${hex.encode(response.CID)}`);
                            assert.equal(response.BCNT, 0, `Expected Response.BCNT to be 0. Got ${response.BCNT}`);
                        })
                } else
                    this.skip()
            })
    })

    it(`P-14

        If CTAPHID_LOCK is implemented, send a valid CTAPHID_LOCK, with lock time set to 8 and:
            (b) while device is locked, send a valid CTAPHID_INIT, on the other CID, and wait for the response:
                (i)  response.CMD MUST be set to CTAPHID_ERROR
                (ii) response.ERRORCODE(DATA[0]) MUST be set to CTAP1_ERR_CHANNEL_BUSY
            (c) send a valid CTAPHID_LOCK, with lock time set to 0
            (b) end a valid CTAPHID_INIT, on the other CID, and wait for the response:
                (i)   response.CID MUST equal to request.CID
                (ii)  response.CMD MUST equal to request.CMD
                (iii) response.NONCE MUST equal to request.NONCE
                (iv)  response.NEWCID MUST be presented
                (v)   response.CTAPHID_VERSION MUST equal to CTAPHID_IF_VERSION(2)
                (vi)  response.DATA size MUST be 17

    `, function() {
        return sendCTAPHID_INITCommand()
            .then((initResponse) => {
                if (initResponse.CAPABILITIES.LOCK) {
                    let buffers = generateRequestFrames(CTAPHID_CMD.CTAPHID_LOCK, [8], initResponse.NEWCID);
                    window.navigator.fido.fido2.hid.sendHIDBuffersSync(getDeviceInfo(), buffers);
                    window.navigator.fido.fido2.hid.readHIDResponseSync(getDeviceInfo(), 700);

                    let nonce = generateRandomBuffer(8);

                    let otherCID = Array.from(initResponse.NEWCID);
                    otherCID[0]++;

                    return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_INIT, nonce, otherCID)
                        .then((result) => {
                            let response = parseCTAPHIDPacket(result);

                            assert.equal(CTAPHID_CMD.CTAPHID_ERROR, response.CMD,
                                `Expected response.CMD to be CTAPHID_ERROR(0x3f). Got ${CTAPHID_CMD[response.CMD]}(${'0x' + hex.encode([response.CMD])})`);
                            assert.equal(1, response.BCNT, `Expected BCNT to be 1. Got ${response.BCNT}`);
                            assert.equal(CTAP_ERROR_CODES.CTAP1_ERR_CHANNEL_BUSY, response.ERRORCODE, `Expected response error code to be (0x). Got ${CTAP_ERROR_CODES[response.ERRORCODE]}(${'0x' + hex.encode([response.ERRORCODE])})`);

                            return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_LOCK, [0], initResponse.NEWCID) // Send unlock
                        })
                        .then((result) => {
                            let response = parseCTAPHIDPacket(result);

                            if (response.CMD === CTAPHID_CMD.CTAPHID_ERROR)
                                throw new Error(`Got an unexpecter error. Error message: ${response.ERRORMSG}`);

                            assert.equal(CTAPHID_CMD.CTAPHID_LOCK, response.CMD);
                            assert.equal(0, response.BCNT);
                            assert.deepEqual(Array.from(initResponse.NEWCID), Array.from(response.CID));

                            return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_INIT, nonce, otherCID)
                        })
                        .then((result) => {
                            let response = parseCTAPHIDPacket(result);

                            assert.equal(response.CMD, CTAPHID_CMD.CTAPHID_INIT, 'response.CMD MUST equal to request.CMD!');
                            assert.deepEqual(response.CID, Array.from(otherCID), 'response.CID MUST equal to request.CID!');
                            assert.deepEqual(response.NONCE, Array.from(nonce), 'response.NONCE MUST equal to request.NONCE!');
                            assert.notDeepEqual(response.NEWCID, [0x00, 0x00, 0x00, 0x00], 'response.NEWCID MUST be presented!');
                            assert.equal(response.IFVERSION, CTAPHID_IF_VERSION, 'response.CTAPHID_VERSION MUST equal to CTAPHID_IF_VERSION(2)!');
                            assert.equal(response.BCNT, 17, 'response.DATA size MUST be 17!');
                        })
                } else 
                    this.skip()
            })
    })
/* ----- LOCK ENDS ----- */

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
        let nonce = generateRandomBuffer(8)

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
        let payload = generateRandomBuffer(32)

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

                let payload    = generateRandomBuffer(1024);

                let pingFrames = generateRequestFrames(CTAPHID_CMD.CTAPHID_PING, payload, NEWCID);

                pingFrames[pingFrames.length - 1].set([pingFrames[1][4] + 1], 4)
    
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
