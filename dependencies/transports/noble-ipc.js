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

const os           = require('os');
const isPrivileged = require('../isPrivileged')();
const { ipcMain }  = require('electron');

/* ----- LOGGER SHENANIGANS ----- */
    let callbackHook = undefined;
    ipcMain.on('logger-async-init-request', (event, arg) => {
        callbackHook = (msg) => {
            event.sender.send('logger-async-reply', msg)
        }
    })

    process.on('uncaughtException', (error) => {
        console.log('Caught "uncaughtException": ', error)

        if(callbackHook)
            callbackHook('Caught "uncaughtException": ', error);
    })

    /**
     * Logs what ever HID API returns
     */
    const logger = (message) => {
        if(callbackHook)
            callbackHook(message);

        console.log(message);
    }

    const noble = (() => { 
        try {
            if(os.platform() === 'win32'
            && os.release().slice(0, 2) === '10') {
                return require('noble-winrt');
            } else if(os.platform() === "darwin") {
                return require('@abandonware/noble');
            } else {
                logger(`PLATFORM "${os.platform()}" UNSUPPORTED PLATFORM`)
                throw new Error(`PLATFORM "${os.platform()}" UNSUPPORTED PLATFORM`);
            }
        } catch(e) {
            logger(`Error connecting to Noble API. The error is: ${e}`)
            throw new Error(`Error connecting to Noble API. The error is: ${e}`);
        }
    })()
/* ----- LOGGER SHENANIGANS END ----- */

/* ----- HELPERS ----- */
    /**
     * Returns string of an object type
     * @param  {object} obj - Given object
     * @return {String}     - String value of a type of an object
     */
    const type = (obj) => {
        return {}.toString.call(obj)
                 .replace(/\[|\]/g, '')
                 .split(' ')[1];
    }

    /**
     * Takes 2byte buffer, and decodes it to BingEndian 16bit integer
     * @param  {TypedArray} buffer
     * @return {Number}
     */
    const readBE16 = (buffer) => {
        buffer = new Uint8Array(Array.from(buffer));
        if(buffer.length !== 2)
            throw new Error('Only 2byte buffer allowed!');

        buffer = getBigEndianEcoding(buffer);

        return new Uint16Array(buffer.buffer)[0]
    }

    /**
     * Returns what endian system does system use
     * @return {String} big/little
     */
    const getEndian = () => {
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
     * Takes arrayBuffer/Uint*Arrays and ensure that it is BigEndian encoded
     * @param  {TypedArray} buff
     * @return {Uint8Array}      - BigEndian encoded typedArray
     */
    const getBigEndianEcoding = (buff) => {
        if (getEndian() === 'big')
            return buff
        else
            return buff.reverse()
    }

    /**
     * Takes arbitrary buffer and returns decoded string.
     * @param  {ArrayBuffer} buffer
     * @return {Integer}
     */
    const arrayBufferToString = (buffer) => {
        return String.fromCharCode.apply(null, new Uint8Array(buffer));
    }


    const ensureBufferType = (probablyBuffer) => {
        return Buffer.from(Array.from(probablyBuffer));
    }
/* ----- HELPERS END ----- */

/* ----- CONSTANTS ----- */
    const ECHO_SERVICE_UUID         = 'fffd';
    const FIDO_SERVICE_UUID_LONG    = '0000fffd00001000800000805f9b34fb';
    const FIDO_SERVICE_UUID_SHORT16 = 'fffd';

    const FIDO_SERVICES_MAP = {
        'f1d0fff1deaaeceeb42fc9ba7ed623bb': 'fidoControlPoint',
        'f1d0fff2deaaeceeb42fc9ba7ed623bb': 'fidoStatus',
        'f1d0fff3deaaeceeb42fc9ba7ed623bb': 'fidoControlPointLength',
        'f1d0fff4deaaeceeb42fc9ba7ed623bb': 'fidoServiceRevisionBitfield',
        '00002a2800001000800000805f9b34fb': 'fidoServiceRevision',
        '2a28': 'fidoServiceRevision'
    }

    const CTAPBLE_ERROR_CODES = {
        0x01: 'ERR_INVALID_CMD', // The command in the request is unknown/invalid
        0x02: 'ERR_INVALID_PAR', // The parameter(s) of the command is/are invalid or missing
        0x03: 'ERR_INVALID_LEN', // The length of the request is invalid
        0x04: 'ERR_INVALID_SEQ', // The sequence number is invalid
        0x05: 'ERR_REQ_TIMEOUT', // The request timed out
        0x06: 'ERR_BUSY',        // The peripheral is busy and can’t accept commands at this time.
        0x7f: 'ERR_OTHER'        // Other, unspecified error
    }

    const CTAPBLE_CMD = {
        'PING':      0x81,
        'KEEPALIVE': 0x82,
        'MSG':       0x83,
        'CANCEL':    0xbe,
        'ERROR':     0xbf,
        0x81: 'PING',
        0x82: 'KEEPALIVE',
        0x83: 'MSG',
        0xbe: 'CANCEL',
        0xbf: 'ERROR'
    }
/* ----- CONSTANTS END ----- */

const peripherals = {};
const defaultRSSI = -80;
let   minRSSI     = -80;

noble.on('stateChange', (state) => {
    if (state === 'poweredOn') {
        noble.startScanning([ECHO_SERVICE_UUID, FIDO_SERVICE_UUID_LONG], true);
    }
})

noble.on('discover', (peripheral) => {
    if(peripheral.rssi < minRSSI) {
        logger(`Skipping connecting to peripheral with UUID(${peripheral.uuid}). Peripheral is too far away. Device RSSI is ${peripheral.rssi}. Min RSSI is ${minRSSI}.`)
        return 
    }
        
    if(!peripherals[peripheral.uuid]) {
        logger('Discovering new peripheral')
        peripherals[peripheral.uuid] = peripheral;
    }

    if(!peripheral.isConnecting && peripheral.state !== 'connected') {
        peripheral.isConnecting = true;
        connectPeripheral(peripheral)
    }
})


/* ----- CONNECTOR METHODS ----- */
    const connectPeripheral = (peripheral) => {
        logger(`Connecting to peripheral ${peripheral.name}`)

        peripheral.connect((error) => {
            peripheral.isConnecting = false
            if(error) {
                logger(`Error connecting peripheral with UUID(${peripheral.uuid}). The message is ${error}`)
            } else {
                setupServices(peripheral)
            }


            peripheral.on('disconnect', () => {
                if(peripherals[peripheral.uuid]) {
                    peripheral.isAvailable = false;
                    peripherals[peripheral.uuid].removeAllListeners();
                    peripherals[peripheral.uuid].requestManager.fail('DISCONNECT');
                    logger('Deleting peripheral ' + peripheral.uuid)
                    delete peripherals[peripheral.uuid];
                }
            })
        })
    }

    const setupServices = (peripheral) => {
        return new Promise((resolve, reject) => {
            peripheral.discoverAllServicesAndCharacteristics((error, services, characteristics) => {
                if(error) {
                    reject(`Error discoveing services and characteristics. The message is: ${error}`)
                } else {
                    for(let service of services) {
                        if(service.uuid === FIDO_SERVICE_UUID_LONG || service.uuid === FIDO_SERVICE_UUID_SHORT16) {
                            peripheral.name                    = `${peripheral.advertisement.localName} (${peripheral.uuid.slice(0, 6).toUpperCase()})`;
                            peripheral.requestManager          = new BLERequestManager(peripheral);
                            peripheral.maxWriteLength          = undefined;
                            peripheral.serviceRevisionBitfield = undefined;
                            peripheral.serviceRevision         = undefined;
                            peripheral.isAvailable             = false; // Tells if current authenticator is available for use.

                            peripheral.characteristics = {};
                            for(let characteristic of service.characteristics) {
                                let characteristicName = FIDO_SERVICES_MAP[characteristic.uuid];
                                peripheral.characteristics[characteristicName] = characteristic;
                            }

                            /* Characteristic promises */
                            let characteristicsPromises = [readPeripheralFIDOCharacteristic(peripheral, 'fidoControlPointLength')]

                            if(peripheral.characteristics['fidoServiceRevisionBitfield']) // FIDO2 and older U2F
                                characteristicsPromises[1] = readPeripheralFIDOCharacteristic(peripheral, 'fidoServiceRevisionBitfield')

                            if(peripheral.characteristics['fidoServiceRevision']) // U2F only
                                characteristicsPromises[2] = readPeripheralFIDOCharacteristic(peripheral, 'fidoServiceRevision')

                            Promise.allSettled(characteristicsPromises)
                            .then((response) => {
                                peripheral.isAvailable = true;
                                if(response[0].status == 'fulfilled') {
                                    peripheral.maxWriteLength = readBE16(response[0].value);
                                } else {
                                    peripheral.isAvailable = false; // Block peripheral if maxWriteLength is not available
                                    throw new Error(`Error reading critical characteristic "maxWriteLength"! The error is: ${response[0].reason}`)
                                }

                                if(response[1].status == 'fulfilled')
                                    peripheral.serviceRevisionBitfield = response[1].value;
                                else {
                                    peripheral.isAvailable = false;
                                    throw new Error(`Error reading "serviceRevisionBitfield" characteristic! The error is: ${response[1].reason}`)
                                }

                                if(response[2].status == 'fulfilled')
                                    peripheral.serviceRevision = arrayBufferToString(response[2].value);
                                else {
                                    logger("SetupServices: " + `Error reading "serviceRevision" characteristic! The error is: ${response[2].reason}`)
                                }

                            })
                            .then(() => {
                                peripheral.isAvailable = true;
                                logger('Successfully connected!')
                                resolve()
                            })
                            .catch((error) => {
                                logger("SetupServices: " + error)
                                reject(error)
                            })

                            break;
                        }
                    }
                }
            })
        })
    }
/* ----- CONNECTOR METHODS END ----- */

/* ----- REQUEST MANAGEMENT CLASS ----- */
    class BLERequestManager {
        constructor(peripheral) {
            this.peripheral = peripheral
        }

        queue            = [];
        currentTask      = undefined;
        currentProtocol  = undefined;

        subscribedToFIDO = false;
        addToQueue(buffers, protocol, bypassKeepAliveCheck) {
            return new Promise((resolve, reject) => {
                let callback = (error, data) => {
                    if(error)
                        reject(error)
                    else
                        resolve(data)
                }

                this.queue = [{buffers, bypassKeepAliveCheck, protocol, callback}].concat(this.queue);
                this.executeNext()
            })
        }

        executeNext() {
            if(!this.currentTask && this.queue.length > 0) {
                this.currentTask = this.queue.pop()
            }

            if(this.currentTask) {
                if(!this.currentProtocol || this.currentProtocol !== this.currentTask.protocol) {
                    initialiseProtocol(this.peripheral, this.currentTask.protocol)
                    this.currentProtocol = this.currentTask.protocol
                }


                if(!this.subscribedToFIDO) {
                    this.subscribedToFIDO = true;
                    this.subscribeAndProcessResponses();
                }

                setTimeout(() => {
                    if(this.currentTask)
                        writeToPeripheralFIDOCharacteristic(this.peripheral, 'fidoControlPoint', this.currentTask.buffers);
                }, 250)
            } else if(this.subscribedToFIDO) {
                this.subscribedToFIDO = false;
                this.currentProtocol  = undefined;
                unsubscribeFromPeripheralFIDOCharacteristic(this.peripheral, 'fidoStatus');
            }
        }

        succeed(buffer) {
            this.currentTask.callback(undefined, buffer);
            this.currentTask = undefined;
        }

        fail(error) {
            if(this.currentTask) {
                this.currentTask.callback(error, undefined);
                this.currentTask = undefined;
            }
        }

        subscribeAndProcessResponses() {
            const Super = this;

            let counter       = 0;
            let lengthCounter = undefined;
            let resultObject  = {};

            const resetState = () => {
                counter       = 0
                lengthCounter = undefined

                resultObject  = {
                    CMD: undefined,
                    LEN: undefined,
                    DATA: Buffer.alloc(0)
                }
            }
            resetState()

            subscribeToPeripheralFIDOCharacteristic(this.peripheral, 'fidoStatus', (error, authentrResponseBuffer, isNotification) => {
                try {
                    if(error) {
                        logger(`Error while receiving authenticator response. The message is: ${error}`);
                        Super.fail(`Error while receiving authenticator response. The message is: ${error}`);
                        return
                    }

                    logger('RECEIVING BLE BUFFER: ' + authentrResponseBuffer.toString('hex'));

                    if(!Super.currentTask) {
                        logger('Received unexpected message...');
                        Super.executeNext();
                        return
                    }

                    /* PROCESSING RESPONSE */
                    if(!resultObject.DATA.length) { //Fresh state
                        resultObject.CMD = authentrResponseBuffer[0];
                        resultObject.LEN = lengthCounter = readBE16(authentrResponseBuffer.slice(1,3));

                        if(!Super.currentTask.bypassKeepAliveCheck && authentrResponseBuffer[0] === CTAPBLE_CMD.KEEPALIVE) {
                            return
                        }

                        authentrResponseBuffer = authentrResponseBuffer.slice(3);
                    } else {
                        if(authentrResponseBuffer[0] !== counter++) {
                            logger('Sequence out of order!');
                            resetState()

                            if(Super.currentTask) {
                                Super.fail('Sequence out of order!');
                            }
                            return
                        }

                        authentrResponseBuffer = authentrResponseBuffer.slice(1);
                    }

                    resultObject.DATA = Buffer.concat([resultObject.DATA, authentrResponseBuffer])
                    lengthCounter     = lengthCounter - authentrResponseBuffer.length;


                    if(!lengthCounter) {
                        Super.succeed(resultObject)
                        resetState()
                        return
                    }
                } catch(error) {
                    logger(`Error while receiving authenticator response. The message is: ${error}`);
                    Super.fail(`Error while receiving authenticator response. The message is: ${error}`);
                }
            })
        }
    }
/* ----- REQUEST MANAGEMENT CLASS ENDS ----- */

/* ----- CORE COMMUNICATION METHODS ----- */
    const subscribeToPeripheralFIDOCharacteristic = (peripheral, characteristicName, callback) => {
        logger('Subscribing to: ' + characteristicName)
        let characteristic = peripheral.characteristics[characteristicName];

        characteristic.on('data', (data, isNotification) => {
            callback(undefined, data, isNotification)
        })

        characteristic.subscribe((error) => {
            if (error)
                callback('Error subscribing to characteristic. Error message is: ' + error);
        })
    }

    let unsubscribeFromPeripheralFIDOCharacteristic = (peripheral, characteristicName) => {
        logger('Unsubscribed from: ' + characteristicName)
        let characteristic = peripheral.characteristics[characteristicName];
        characteristic.unsubscribe((error) => {
            if(error) {
                logger('Failed to unsubscribe from characteristic. Error message is: ' + error);
                throw new Error('Failed to unsubscribe from characteristic. Error message is: ' + error);
            }
        })
    }

    const readPeripheralFIDOCharacteristic = (peripheral, characteristicName) => {
        return new Promise((resolve, reject) => {
            let characteristic = peripheral.characteristics[characteristicName];

            if(!characteristic)
                reject(characteristicName + ' is an unknown characteristic!');

            characteristic.read((error, data) => {
                if(error) {
                    reject('Error reading characteristic. Error message is: ' + error)
                    return
                }

                resolve(data)
            })
        })
    }

    const writeToPeripheralFIDOCharacteristic = (peripheral, characteristicName, buffers, writeWithoutResponse) => {
        let characteristic = peripheral.characteristics[characteristicName];
        for(let buffer of buffers) {
            logger(`WRITING BLE BUFFER TO "${characteristicName}": ${buffer.toString('hex')}`);
            characteristic.write(buffer, writeWithoutResponse);
        }
    }

    const initialiseProtocol = (peripheral, protocol) => {
        let protocols = {
            'fido2': 0x20,
            'u2f12': 0x40,
            'u2f11': 0x80
        }

        logger('Selecting BLE apple fort protocol: ' + protocol)

        if(!peripheral.characteristics['fidoServiceRevisionBitfield'])
            throw new Error('Can not initialise authenticator! Authenticator missing "fidoServiceRevisionBitfield" characteristic!');

        let protocolBuffer = Buffer.from([protocols[protocol]])

        writeToPeripheralFIDOCharacteristic(peripheral, 'fidoServiceRevisionBitfield', [protocolBuffer])
    }    
/* ----- CORE COMMUNICATION METHODS END ----- */

/* ----- IPC ----- */
    let getAllServicesForThePeripheral = (peripheral) => {
        let services = {};
        for(let service of peripheral.services) {
            let serv = {
                'name': service.name,
                'type': service.type,
                'uuid': service.uuid,
                'characteristics': {}
            }

            for(let characteristic of service.characteristics) {
                let char = {
                    'descriptors': characteristic.descriptors,
                    'name': characteristic.name,
                    'properties': characteristic.properties,
                    'type': characteristic.type,
                    'uuid': characteristic.uuid
                } 

                serv.characteristics[characteristic.uuid] = char;
            }

            services[service.uuid] = serv;
        }

        return services
    }

    const getPeripheral = (deviceInfo) => {
        return peripherals[deviceInfo.uuid]
    }

    const sendSuccess = (id, event, data) => {
        event.sender.send(id, {
            'status': 'ok',
            'data': data
        })
    }

    const sendFail = (id, event, error) => {
        event.sender.send(id, {
            'status': 'error',
            'error': error
        })
    }

    ipcMain.on('sendFIDOBuffers-async-request', (event, arg) => {
        try {
            const deviceInfo           = arg.deviceInfo;
            const protocol             = arg.protocol;
            const buffers              = arg.buffers.map((buffer) => ensureBufferType(buffer))
            const bypassKeepAliveCheck = arg.bypassKeepAliveCheck;
            const peripheral           = getPeripheral(deviceInfo);

            let timeoutError = setTimeout(() => {
                // noble.startScanning();
                if(peripheral)
                    peripheral.requestManager.fail('CANCELED');

                sendFail('sendFIDOBuffers-async-response', event, 'TIMEOUT')
            }, 10000 || arg.timeout)

            if(peripheral && peripheral.state === 'connected') {
                // noble.stopScanning();

                peripheral.requestManager.addToQueue(buffers, protocol, !!bypassKeepAliveCheck)
                .then((response) => {
                    clearTimeout(timeoutError);
                    response.DATA = new Uint8Array(Array.from(response.DATA));
                    logger('SUCCESSFULLY RECEIVED RESPONSE!')
                    sendSuccess('sendFIDOBuffers-async-response', event, response)
                })
                .catch((error) => {
                    clearTimeout(timeoutError);
                    logger('ERROR WHILE RECEIVING RESPONSE: ' + error)
                    sendFail('sendFIDOBuffers-async-response', event, error)
                })
            } else
                sendFail('sendFIDOBuffers-async-response', event, `No peripheral with UUID${deviceInfo.uuid.slice(0, 6)} found!`);

        } catch(error) {
            logger(error)
            sendFail('sendFIDOBuffers-async-response', event, error)
        }
    })

    ipcMain.on('getFIDOCharacteristics-sync', (event, deviceInfo) => {
        let peripheral = getPeripheral(deviceInfo);

        let characteristics = {};
        for(let id in peripheral.characteristics) {
            let char = {
                'descriptors': peripheral.characteristics[id].descriptors,
                'name': peripheral.characteristics[id].name,
                'properties': peripheral.characteristics[id].properties,
                'type': peripheral.characteristics[id].type,
                'uuid': peripheral.characteristics[id].uuid
            } 

            characteristics[id] = char;
        }

        event.returnValue = characteristics
    })

    ipcMain.on('getMaxWriteLength-sync', (event, deviceInfo) => {
        let peripheral    = getPeripheral(deviceInfo);
        event.returnValue = peripheral.maxWriteLength;
    })

    ipcMain.on('getServiceRevisionBitfield-sync', (event, deviceInfo) => {
        let peripheral    = getPeripheral(deviceInfo);
        event.returnValue = peripheral.serviceRevisionBitfield;
    })

    ipcMain.on('getServiceRevision-sync', (event, deviceInfo) => {
        let peripheral    = getPeripheral(deviceInfo);
        event.returnValue = peripheral.serviceRevision;
    })

    ipcMain.on('getPrimaryService-sync', (event, deviceInfo) => {
        let returnValue = '';
        try {
            let peripheral = getPeripheral(deviceInfo);
            returnValue = peripheral.advertisement.serviceData[0] || '';
        } catch(e) {
            logger('Error while getting primary service!: Message is: ' + e);
        }

        event.returnValue = returnValue;
    })

    ipcMain.on('getConnectedDevices-sync', (event) => {
        let blePeripherals = [];
        for(let uuid in peripherals) {
            let peripheral = peripherals[uuid];
            let deviceInfo = {
                'transport': 'BLE',
                'uuid': uuid,
                'product': peripheral.name,
                'maxWriteLength': peripheral.maxWriteLength
            }

            blePeripherals.push(deviceInfo)
        }

        event.returnValue = blePeripherals.sort((a, b) => a.name < b.name)
    })

    ipcMain.on('getAllServices-sync', (event, deviceInfo) => {
        let peripheral    = getPeripheral(deviceInfo);
        event.returnValue = getAllServicesForThePeripheral(peripheral);
    })

    ipcMain.on('getState-sync', (event, deviceInfo) => {
        let peripheral = getPeripheral(deviceInfo);
        if(!peripheral || !peripheral.isAvailable) {
            event.returnValue = 'disconnected';
            return
        }

        event.returnValue = getPeripheral(deviceInfo).state
    })

    ipcMain.on('getRSSI-sync', (event, deviceInfo) => {
        if(!getPeripheral(deviceInfo)) {
            event.returnValue = '> -100';
            return
        }

        event.returnValue = getPeripheral(deviceInfo).rssi
    })

    ipcMain.on('setRSSI-sync', (event, newValue) => {
        minRSSI = newValue;
        logger('SETTING NEW RSSI VALUE: ' + newValue)
        event.returnValue = true
    })

    ipcMain.on('resetRSSI-sync', (event) => {
        minRSSI = defaultRSSI;
        logger('RESETTING RSSI TO: ' + defaultRSSI)
        event.returnValue = true
    })

    ipcMain.on('bleDeviceExist-sync', (event, deviceInfo) => {
        if(!deviceInfo || !deviceInfo.uuid || !getPeripheral(deviceInfo)) {
            event.returnValue = false;
        } else {
            event.returnValue = true;
        }
    })

    ipcMain.on('disableBLE-sync', (event, deviceInfo) => {
        // BLEIsEnabled = false;
        // noble.stopScanning();
        logger('NOT ENABLED. TODO: Stopped Scanning!');
        event.returnValue = true;
    })

    ipcMain.on('enableBLE-sync', (event, deviceInfo) => {
        // BLEIsEnabled = true;
        // noble.startScanning([ECHO_SERVICE_UUID, FIDO_SERVICE_UUID_LONG], true);
        logger('NOT ENABLED. TODO: Starting Scanning!');
        event.returnValue = true;
    })

    ipcMain.on('resetDevices-sync', (event, deviceInfo) => {
        queue = {};
        for(let peripheral of peripherals)
            peripherals.disconnect();

        event.returnValue = true;
    })
/* ----- IPC ENDS ----- */