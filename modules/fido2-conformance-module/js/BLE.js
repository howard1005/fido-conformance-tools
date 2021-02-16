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

let CTAPBLE_CMD = {
    PING:      0x81,
    KEEPALIVE: 0x82,
    MSG:       0x83,
    CANCEL:    0xbe,
    ERROR:     0xbf
}
Object.assign(CTAPBLE_CMD, inverseDictionary(CTAPBLE_CMD))

/**
 * Generates BLE request frames based on the authenticator limitations
 * @param  {Number} command        - FIDOBLE command
 * @param  {Buffer} requestBuffer  - Request buffer
 * @param  {DeviceInfo} deviceInfo - DeviceInfo
 * @return {Array<Buffer>}         - Return, lol
 */
let generateBLERequestFrames = (command, requestBuffer, deviceInfo) => {
    let maxWriteLength = navigator.fido.fido2.ble.getMaxWriteLength(deviceInfo);

    let ffk        = (requestBuffer.length - (maxWriteLength - 3));
    let frameCount = 1 + ((ffk / Math.abs(ffk) + 1) * Math.ceil(ffk / (maxWriteLength - 1)) / 2) || 1;

    let frames      = [];
    let contCounter = 0;
    for(let i = 0; i < frameCount; i++) {
        let frame = new Uint8Array(maxWriteLength);
        if(i === 0) {
            frame.set([command]);
            frame.set(getBigEndianEcoding(new Uint16Array([requestBuffer.byteLength])), 1);
            frame.set(requestBuffer.slice(0, maxWriteLength - 3), 3);

            if(i + 1 === frameCount)
                frame = frame.slice(0, 3 + requestBuffer.length);

            requestBuffer = requestBuffer.slice(maxWriteLength - 3)
        } else {
            frame.set([contCounter++]);
            frame.set(requestBuffer.slice(0, maxWriteLength - 1), 1);

            if(i + 1 === frameCount)
                frame = frame.slice(0, 1 + requestBuffer.length);

            requestBuffer = requestBuffer.slice(maxWriteLength - 1)
        }

        frames.push(frame);
    }

    return frames
}

/**
 * Send CTAPBLE_CBOR command
 * @param  {Buffer} requestBuffer - request buffer
 * @return {Promise<CTAP2Response>}
 */
let sendCTAPBLE_Command = (command, requestBuffer) => {    
    return BLEGracePeriod()
    .then(() => BLEWaitForAuthenticatorToConnect(15000))
    .then(() => {
        let frames = generateBLERequestFrames(command, requestBuffer, getDeviceInfo());
        return window.navigator.fido.fido2.ble.sendFIDOBuffers(getDeviceInfo(), frames, 'fido2')
    })
    .then((response) => {
        if(response.CMD !== CTAPBLE_CMD.MSG)
            throw new Error(`Expected authenticator to return CMD MSG(0x83). Got ${CTAPBLE_CMD[response.CMD]}(${response.CMD})`)

        return response.DATA
    })
}

/**
 * Send CTAPBLE_CBOR command
 * @param  {Buffer} requestBuffer - request buffer
 * @return {Promise<CTAP2Response>}
 */
let sendCTAPBLE_CBORCommand = (requestBuffer) => {
    return sendCTAPBLE_Command(CTAPBLE_CMD.MSG, requestBuffer)
}

/**
 * If BLE device selected, waits defined amount of time(default 2s)
 * @param  {Int} maxTimeoutMs - max timeout
 * @return {Promise} - always resolves
 */
let BLEGracePeriod = (maxTimeoutMs) => {
    maxTimeout = maxTimeout || window.config.test.CustomBLEGracePeriod || 750;
    return new Promise((resolve, reject) => {
        if(getDeviceInfo().transport === 'BLE')
            setInterval(() => resolve(), maxTimeoutMs || 2000);
        else
            resolve();
    })
}


/**
 * Waits for BLE authenticator specified amount to connect
 * @param  {Int} timeoutMs - length of time till timeout(default 20s)
 * @return {Promise}
 */
let BLEWaitForAuthenticatorToConnect = (timeoutMs) => {
    if(getDeviceInfo().transport === 'BLE') {
        return new Promise((resolve, reject) => {
            if(navigator.fido.fido2.ble.getState(getDeviceInfo()) === 'connected') {
                resolve()
            } else {
                setTimeout(() => {
                    alert('Waiting for an authenticator to connect...')
                }, 1)

                let maxTimeout  = timeoutMs || 20 * 1000;
                let tryInterval = setInterval(() => {
                    if(navigator.fido.fido2.ble.getState(getDeviceInfo()) === 'connected')
                        resolve()
                    else {
                        if(maxTimeout <= 0) {
                            clearInterval(tryInterval)
                            reject('TIMEOUT')
                        }
                    }

                    maxTimeout += -500
                }, 500)
            }
        })
    } else {
        return Promise.resolve()
    }
}

