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

const hid = require('node-hid');
const os  = require('os');

const currentPlatform = os.platform();
let openedDevices     = {};

const FIDO_USAGE_PAGE   = 0xF1D0;
const FIDO_USAGE_CTAP   = 1;
const CTAPHID_ERROR     = 0x80 | 0x3f;
const CTAPHID_KEEPALIVE = 0x80 | 0x3b;
const CTAPHID_MSG       = 0x80 | 0x03;
const CTAPHID_CANCEL    = 0x80 | 0x11;
const SW_CONDITIONS_NOT_SATISFIED = 0x6985;

let HID_PACKET_SIZE = 0x40;

/* ----- UTILS ----- */
    let seqToBuffer = (buffer) => {
        return Buffer.from(Array.from(buffer));
    }

    let readBE16 = (buffer) => {
        buffer = seqToBuffer(buffer);
        if(buffer.length !== 2)
            throw new Error('Only 2byte buffer allowed!');

        return buffer.readInt16BE(0)
    }

    let readBE32 = (buffer) => {
        buffer = seqToBuffer(buffer);
        if(buffer.length !== 4)
            throw new Error('Only 4byte buffers allowed!');

        return buffer.readInt32BE(0)
    }

    /**
     * Opens device defined by given deviceInfo
     * @param  {DeviceInfo} deviceInfo - Node HID device info object
     * @return {NodeHIDDevice}
     */
    let openDevice = (deviceInfo) => {
        if (deviceInfo && deviceInfo.path) {
            if (!openedDevices[deviceInfo.path]) {
                let newDevice = new hid.HID(deviceInfo.path);
                openedDevices[deviceInfo.path] = newDevice;
                return newDevice;
            } else {
                openedDevices[deviceInfo.path].resume();
                return openedDevices[deviceInfo.path];
            }
        } else
            throw new Error('Given DeviceInfo is not a valid DeviceInfo object!');
    }

    /**
     * Closes device defined by given deviceInfo
     * @param  {DeviceInfo} deviceInfo - Node HID device info object
     */
    let closeDevice = (deviceInfo) => {
        if (deviceInfo && deviceInfo.path) {
            if (openedDevices[deviceInfo.path]) {
                openedDevices[deviceInfo.path].close();
                openedDevices[deviceInfo.path] = undefined;
            }
        } else
            throw new Error('Given DeviceInfo is not a valid DeviceInfo object!');
    }

    /**
     * Send FIDOHID CANCEL(0x91)
     * @param  {DeviceInfo} deviceInfo
     * @param  {Buffer}     cid
     */
    let sendCancel = (deviceInfo, cid) => {
        let possiblyKeepAliveBuffer = readSync(deviceInfo);

        if(Buffer.from(cid).toString('hex') !== 'ffffffff') {
            let buff = new Buffer(HID_PACKET_SIZE).map((byte) => 0);

            if(!deviceInfo || !cid)
                throw new Error('Missing cid or deviceInfo!');

            buff.set(cid);
            buff[4] = CTAPHID_CANCEL;
            process.send({
                'status': 'success',
                'cmd': 'logger',
                'data': 'HID DATA SENT: ' + buff.toString('hex')
            })

            writeHIDBuffers(deviceInfo, [buff]);

            let responseBuffer = readSync(deviceInfo);
            let resp = Buffer.from(responseBuffer).toString('hex');
            process.send({
                'status': 'success',
                'cmd': 'logger',
                'data': 'HID DATA READ: ' + resp
            })

            return responseBuffer
        }

        return Buffer.from([])
    }


    /**
     * Write HID buffers to FIDO device
     * @param  {DeviceInfo} deviceInfo
     * @param  {Array<Buffers>} buffers
     */
    let writeHIDBuffers = (deviceInfo, buffers) => {
        console.log('Writing HID buffers: ')
        let device = openDevice(deviceInfo);

        /**
         * Node HID `write` freezes if the buffer is not an Array
         */
        for(let buffer of buffers) {
            buffer = Array.from(buffer);
            console.log(Buffer.from(buffer).toString('hex'))

            if(buffer[0] === 0x00 || currentPlatform === 'win32')
                buffer = [0x00].concat(buffer);

            device.write(buffer);
        }
    }

    /**
     * Checks that response buffer is fine
     * @param  {Buffer} data   - response buffer
     * @return {Boolean}       - ok or not
     */
    let responseIsOK = (data) => {
        if(!data || !data.length)
            return false;
 
        /* IF authenticator is waiting for user action */
        if(data[4] === CTAPHID_MSG && readBE16(data.slice(7,9)) === SW_CONDITIONS_NOT_SATISFIED) {
            console.log('WAITING FOR TEST OF USER PRESENCE OR USER VERIFCATION!')
            return false
        }

        /* IF CTAP2 KEEPALIVE(authenticator is busy) */
        if(data[4] === CTAPHID_KEEPALIVE)
            return false

        return true
    }

    let tryReadResponse = (device) => {
        try {
            let resp = device.readTimeout(300);
            return new Uint8Array(resp);
        } catch (error) {
            console.log('Error: ', error);
            return new Uint8Array()
        }
    }

    let deviceInfoIsOk = (deviceInfo) => {
        try {
            openDevice(deviceInfo);
            closeDevice(deviceInfo);
            return true
        } catch(error) {
            console.log('Error: ', error)
            return false
        }
    }

/* ----- UTILS ENDS ----- */

process.on('message', (request) => {
    let cmd              = request.cmd;
    let timeout          = request.timeout;
    let deviceInfo       = request.deviceInfo;
    let buffersArray     = request.buffersArray;
    let customPacketSize = request.customPacketSize;
    let options          = request.options;
    let cid              = request.cid;

    let response = undefined;
    if(deviceInfo && !deviceInfoIsOk(deviceInfo)) {
        response = {
            'status': 'fail',
            'cmd': cmd,
            'error': `Failed to open device "${deviceInfo.product}"! Most likely device is not plugged in.`
        }
        process.send(response);

        return
    }

    switch(cmd) {
        case 'sendHIDBuffers':
            try {
                if(!deviceInfo || !buffersArray)
                    throw new Error('Missing deviceInfo and/or buffersArray arguments!');

                sendRequestAndWaitForResponse(deviceInfo, buffersArray, timeout, options)
                    .then((result) => {
                        response = {
                            'status': 'ok',
                            'cmd': 'sendHIDBuffers',
                            'data': result
                        }
                        process.send(response);
                    })
                    .catch((error) => {
                        response = {
                            'status': 'fail',
                            'cmd': 'sendHIDBuffers',
                            'error': error
                        }
                        process.send(response);
                    })
            } catch(error) {
                response = {
                    'status': 'fail',
                    'cmd': 'sendHIDBuffers',
                    'error': error
                }
                process.send(response);
            }
        break;

        case 'sendCancel':
            try {
                let responseBuffer = sendCancel(deviceInfo, cid);
                response = {
                    'status': 'ok',
                    'cmd': 'sendCancel',
                    'data': responseBuffer
                }
            } catch(error) {
                console.log('ERROR SENDING CANCEL', error)
                response = {
                    'status': 'fail',
                    'cmd': 'sendCancel',
                    'error': `ERROR SENDING CANCEL: ${error}`
                }
            }
            process.send(response);
        break;

        case 'sendHIDBuffersSync':
            try {
                writeHIDBuffers(deviceInfo, buffersArray)
                response = {
                    'status': 'ok',
                    'cmd': 'sendHIDBuffersSync'
                }
            } catch(error) {
                response = {
                    'status': 'fail',
                    'cmd': 'sendHIDBuffersSync',
                    'error': error
                }
            }

            process.send(response);
        break;

        case 'readHIDBuffersSync':
            try {
                let data = readSync(deviceInfo, timeout)
                response = {
                    'status': 'ok',
                    'cmd': 'readHIDBuffersSync',
                    'data': data
                }
            } catch(error) {
                response = {
                    'status': 'fail',
                    'cmd': 'readHIDBuffersSync',
                    'error': error
                }
            }

            process.send(response);
        break;

        case 'getAllDevices':
            response = {
                'status': 'ok',
                'cmd': 'getAllDevices',
                'data': getAllDevices()
            }
            process.send(response);
        break;

        case 'getFIDODevices':
            response = {
                'status': 'ok',
                'cmd': 'getFIDODevices',
                'data': getFIDODevices()
            }
            process.send(response);
        break;

        case 'setCustomPacketSize':
            console.log('SETTING NEW HID PACKET SIZE: ', customPacketSize)
            HID_PACKET_SIZE = customPacketSize;
            response = {
                'status': 'ok',
                'cmd': 'setCustomPacketSize'
            }
            process.send(response);
        break;
    }
})

/* ----- IPC ----- */
    let readSync = (deviceInfo, timeout) => {
        let device = openDevice(deviceInfo);
        device.resume();

        timeout = timeout || 100;

        let response = Array.from(device.readTimeout(timeout));

        if (!response.length)
            return []

        return response
    }

    let sendRequestAndWaitForResponse = (deviceInfo, buffersArray, timeout, options) => {
        let recordedCID = undefined;
        return new Promise((resolve, reject) => {
            timeout = timeout || 10000;
            try {
                recordedCID = buffersArray[0].slice(0, 4);

                closeDevice(deviceInfo)
                let device = openDevice(deviceInfo);

                let results = [];

                let startTime = Math.floor(Date.now());
                writeHIDBuffers(deviceInfo, buffersArray);

                let counter = 0;
                let poller  = setInterval(() => {
                    let data = tryReadResponse(device)

                    console.log('Receiving HID buffers: ' + Buffer.from(data).toString('hex'))

                    /* You know, like finish him in mortal combat, but finish HID */
                    let finishHID = () => {
                        // sendCancel(deviceInfo, recordedCID);
                        closeDevice(deviceInfo)
                        clearInterval(poller);
                    }

                    /* If response is a cont frame, or it's not WAITING FOR USER ACTION type */
                    if((results.length || responseIsOK(data)) && data.length === HID_PACKET_SIZE) {
                        if(responseIsOK(data))
                            results.push(data);
                    } else {
                        if(options && options.keepSendingCMDs) {
                            console.log('RESENDING REQUEST')
                            writeHIDBuffers(deviceInfo, buffersArray);
                        }
                    }

                    if(results.length && (!responseIsOK(data) || data.length !== HID_PACKET_SIZE)) {
                        results = results.map((resp) => Array.from(resp));
                        resolve(results)
                        finishHID();
                        return
                    }

                    if(Math.floor(Date.now()) > startTime + timeout) {
                        reject('HIDFORK: TIMEOUT!');
                        finishHID();
                        return
                    }
                }, 25)     
            } catch (error) {
                console.log('Error: ', error);
                reject(error);
                closeDevice(deviceInfo)
            }
        })
    }

    /**
     * Returns a list of available FIDO devices
     * @return {DeviceInfo[]}
     */
    let getFIDODevices = () => {
        let hiddevices = hid.devices();

        let fidodevices = [];
        for(let device of hiddevices) {
            if(device.usagePage == FIDO_USAGE_PAGE && device.usage == FIDO_USAGE_CTAP) {
                device.transport = 'HID';
                fidodevices.push(device);
            }
        }

        return fidodevices
    }

    /**
     * Returns a list of all available HID devices
     * @return {DeviceInfo[]}
     */
    let getAllDevices = () => {
        let devices = hid.devices();

        for(let device of devices)
            device.transport = 'HID';

        return devices
    }
/* ----- IPC END ----- */
