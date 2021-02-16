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

const {ipcRenderer} = require('electron');

let buffersToHexLines = (buffersArray) => {
    let bufferStrings = ''
    for(let buff of buffersArray)
        bufferStrings += hex.encode(buff) + '\n';

    return bufferStrings
}

let getDeviceState = (deviceInfo) => {
    let fidoDevices = ipcRenderer.sendSync('get-fido-devices-sync', '');

    for(let device of fidoDevices) {
        if(deviceInfo.path === device.path)
            return 'ready'
    }

    return 'disconnected'
}

let hash = (hashFunction, data) => (hashFunction, data) => {
    if(!hashFunction)
        throw new Error('hashFunction argument is missing!');

    hashFunction = hashFunction.replace('-', '');

    if(!data)
        throw new Error('data argument is missing!');

    let hash = crypto.createHash(hashFunction);
    hash.update(data);

    return new Uint8Array(hash.digest())
}

/**
 * Returns what endian system does system use
 * @return {String} big/little
 */
var getEndian = () => {
    let arrayBuffer = new ArrayBuffer(2);
    let uint8Array = new Uint8Array(arrayBuffer);
    let uint16array = new Uint16Array(arrayBuffer);
    uint8Array[0] = 0xAA; // set first byte
    uint8Array[1] = 0xBB; // set second byte

    if(uint16array[0] === 0xBBAA)
        return 'little';

    if(uint16array[0] === 0xAABB)
        return 'big';

    else
        throw new Error('Something crazy just happened!');
}

/**
 * Converts any given typed array or arrayBuffer to Uint8
 * @param  {typeObject} obj
 * @return {Uint8Array}
 */
var convertToUint8Array = (obj) => {
    let objectType = type(obj)
    if( objectType != 'Uint8Array' &&
        objectType != 'Uint16Array' &&
        objectType != 'Uint32Array' &&
        objectType != 'ArrayBuffer' )
       throw new TypeError('Only Uint8/16/32Array and ArrayBuffer allowed!')

    if(objectType == 'ArrayBuffer')
        return new Uint8Array(obj.slice())
    else
        return new Uint8Array(obj.buffer.slice())

    return temp
}

/**
 * Takes arrayBuffer/Uint*Arrays and ensure that it is BigEndian encoded
 * @param  {TypedArray} buff
 * @return {Uint8Array}      - BigEndian encoded typedArray
 */
var getBigEndianEcoding = (buff) => {
    buff = convertToUint8Array(buff);

    if (getEndian() === 'big')
        return buff
    else
        return buff.reverse()
}

/**
 * Takes 4byte buffer, and decodes it to BingEndian 32bit integer
 * @param  {TypedArray} buffer
 * @return {Number}
 */
var readBE32 = (buffer) => {
    buffer = convertToUint8Array(buffer);

    if(buffer.length !== 4)
        throw new Error('Only 4byte buffers allowed!');

    buffer = getBigEndianEcoding(buffer);

    return new Uint32Array(buffer.buffer)[0]
}

module.exports = {
    'sendHIDBuffers': (deviceInfo, buffersArray, timeout, options) => {
        if(!deviceInfo || !buffersArray)
            throw new Error('Missing deviceInfo and/or buffersArray arguments!');

        buffersArray = buffersArray.map((buff) => Array.from(buff));
        let requestPayload = {deviceInfo, buffersArray, timeout, options}
       
        return new Promise((resolve, reject) => {
            ipcRenderer.once('send-hid-buffers-async-reply', (event, response) => {
                if(response.status === 'ok') {
                    console.log('HID DATA RECEIVED: ' + buffersToHexLines(response.data))
                    resolve(response.data)
                } else
                    reject(response.error)
            })

            let deviceConnected = getDeviceState(deviceInfo) === 'ready';
            if(deviceConnected) {
                 ipcRenderer.send('send-hid-buffers-async-message', requestPayload)
                 console.log('HID DATA SENT: ' + buffersToHexLines(buffersArray));
            } else {
                setTimeout(() => {
                    alert('Waiting for authenticator to be connected...')
                }, 1)

                let timeoutInterval = setTimeout(() => {
                    clearInterval(tryInterval)
                    throw new Error('TIMEOUT')
                }, 10000)

                let tryInterval = setInterval(() => {
                    deviceConnected = getDeviceState(deviceInfo) === 'ready';
                    if(deviceConnected) {
                        clearInterval(timeoutInterval);
                        clearInterval(tryInterval);
                        ipcRenderer.send('send-hid-buffers-async-message', requestPayload)
                        console.log('HID DATA SENT: ' + buffersToHexLines(buffersArray));
                    }
                }, 1000)
            }
        })
    },

    'sendHIDBuffersSync': (deviceInfo, buffersArray) => {
        if(!deviceInfo || !buffersArray)
            throw new Error('Missing deviceInfo and/or buffersArray arguments!');

        buffersArray = buffersArray.map((buff) => Array.from(buff));

        console.log('HID DATA SENT: ' + buffersToHexLines(buffersArray));

        let requestPayload = {deviceInfo, buffersArray}
        let resp = ipcRenderer.sendSync('send-hid-buffers-sync', requestPayload);

        if(resp.status === 'ok')
            return undefined
        else {
            console.log(resp)
            throw new Error('HID API returned error: ' + resp.error);
        }
    },

    /**
     * Synchronously reads device response
     * @param  {DeviceInfo} deviceInfo     - Node HID device info object
     * @return {ArrayBuffer}
     */
    'readHIDResponseSync': (deviceInfo, timeout) => {
        let requestPayload = {deviceInfo, timeout}

        let response = ipcRenderer.sendSync('read-hid-response-sync', requestPayload);

        if(response.status === 'ok') {
            console.log('HID DATA READ: ' + hex.encode(response.data))
            return response.data
        } else
            throw new Error('HID API returned error: ' + response.error);
    },

    'sendHIDCancel': (deviceInfo, cid) => {
        if(!deviceInfo || !cid)
            throw new Error('Missing deviceInfo and/or cid arguments!');

        let resp = ipcRenderer.sendSync('send-hid-cancel-sync', {deviceInfo, cid});

        if(resp.status === 'ok')
            return resp.data
        else {
            console.log(resp)
            throw new Error('HID API returned error: ' + resp.error);
        }
    },

    'closeHIDDevice': (deviceInfo) => {
        let resp = ipcRenderer.sendSync('close-device-sync', deviceInfo);

        if(resp.status === 'ok')
            return undefined
        else {
            console.log(resp)
            throw new Error('HID API returned error: ' + resp.error);
        }
    },

    'getDevices': () => {
        let devices = ipcRenderer.sendSync('get-fido-devices-sync', '');
        return devices.sort((A, B) => {
            if(A.product === B.product) {
                let hashA = hash('sha256', JSON.stringify(A));
                let hashB = hash('sha256', JSON.stringify(B));

                if(readBE32(hashA.slice(0, 4)) > readBE32(hashB.slice(0, 4))) {
                    A.product = `(1) ${A.product}`;
                    B.product = `(2) ${B.product}`;

                    return true
                } else {
                    B.product = `(1) ${B.product}`;
                    A.product = `(2) ${A.product}`;

                    return false
                }
            } else
                return A.product > B.product
        })
    },

    'setCustomPacketSize': (size) => {
        if(!size || typeof size !== "number" || size < 8)
            throw new Error('The size of the packet MUST be a number, with a value of at least 8!')

        return ipcRenderer.sendSync('set-custom-packet-size-sync', size);
    },

    'resetPacketSize': (size) => {
        return ipcRenderer.sendSync('set-custom-packet-size-sync', 64);
    },

    'getState': (deviceInfo) => {
        return getDeviceState(deviceInfo)
    },

    'getAllDevices': () => {
        return ipcRenderer.sendSync('get-all-devices-sync', '')
    }
}
