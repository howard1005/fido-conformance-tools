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

const pcsclite      = require('pcsclite');
const isPrivileged  = require('../isPrivileged')();
const os            = require('os');

let APDU_STATUS_CODES = {
    0x9000: 'SW_NO_ERROR',
    0x6100: 'SW_BYTES_REMAINING_00',
    0x6700: 'SW_WRONG_LENGTH',
    0x6982: 'SW_SECURITY_STATUS_NOT_SATISFIED',
    0x6983: 'SW_FILE_INVALID',
    0x6984: 'SW_DATA_INVALID',
    0x6985: 'SW_CONDITIONS_NOT_SATISFIED',
    0x6986: 'SW_COMMAND_NOT_ALLOWED',
    0x6999: 'SW_APPLET_SELECT_FAILED',
    0x6A80: 'SW_WRONG_DATA',
    0x6A81: 'SW_FUNC_NOT_SUPPORTED',
    0x6A82: 'SW_FILE_NOT_FOUND',
    0x6A83: 'SW_RECORD_NOT_FOUND',
    0x6A86: 'SW_INCORRECT_P1P2',
    0x6B00: 'SW_WRONG_P1P2',
    0x6C00: 'SW_CORRECT_LENGTH_00',
    0x6D00: 'SW_INS_NOT_SUPPORTED',
    0x6E00: 'SW_CLA_NOT_SUPPORTED',
    0x6F00: 'SW_UNKNOWN',
    0x6A84: 'SW_FILE_FULL',
    0x6881: 'SW_LOGICAL_CHANNEL_NOT_SUPPORTED',
    0x6882: 'SW_SECURE_MESSAGING_NOT_SUPPORTED',
    0x6200: 'SW_WARNING_STATE_UNCHANGED'
}

/**
 * Takes 2byte buffer, and decodes it to BingEndian 16bit integer
 * @param  {TypedArray} buffer
 * @return {Number}
 */
var readBE16 = (buffer) => {
    buffer = convertToUint8Array(buffer);

    if(buffer.length !== 2)
        throw new Error('Only 2byte buffer allowed!');

    buffer = getBigEndianEcoding(buffer);

    return new Uint16Array(buffer.buffer)[0]
}

class NFCReader {
    constructor(reader) {
        this.reader        = reader;
        this.queue         = [];
        this.busy          = false;
        this.initialised   = false;
        this.cardInserted  = false;
        this.protocol      = undefined;
        this.authrIsReset  = true;

        let connect    = (protocol) => {this.protocol = protocol; this.cardInserted = true}
        let disconnect = () => {this.initialised = false; this.cardInserted = false}
        reader.on('status', function(status) {
            var changes = this.state ^ status.state;
            if (changes) {
                if ((changes & this.SCARD_STATE_EMPTY) && (status.state & this.SCARD_STATE_EMPTY)) {
                    console.log('Card removed')
                    reader.disconnect(reader.SCARD_LEAVE_CARD, (err) => {
                        if (err) {
                            console.error(`Error disconnecting the card! The message is: ${err}`);
                        } else {
                            disconnect();
                            console.log('Card was removed!');
                        }
                    });
                } else if ((changes & this.SCARD_STATE_PRESENT) && (status.state & this.SCARD_STATE_PRESENT)) {
                    console.log('Card inserted')
                    reader.connect({ share_mode : this.SCARD_SHARE_SHARED }, (err, protocol) => {                    
                        if (err) {
                            console.error(`Error connecting to card! The message is: ${err}`);
                        } else {
                            connect(protocol)
                            console.log(`Selected protocol "${protocol}" for reader "${reader.name}"`);
                        }
                    })
                }
            }
        })
    }

/* ----- DATA EXCHANGE ----- */
    resetCardState() {
        if(!this.dontResetCard()) {
            return new Promise((resolve, reject) => {
                let Super = this;
                Super.reader.disconnect(Super.reader.SCARD_LEAVE_CARD, function(err) {
                    if (err) {
                        console.error(`Error disconnecting the card! The message is: ${err}`);
                        reject(`Error disconnecting the card! The message is: ${err}`)
                    } else {
                        Super.initialised = false;
                        Super.reader.connect({ share_mode : Super.reader.SCARD_SHARE_SHARED }, function(err, protocol) {                    
                            if (err) {
                                console.error(`Error connecting to card! The message is: ${err}`);
                                reject(`Error connecting to card! The message is: ${err}`)
                            } else {
                                Super.protocol = protocol
                                console.log(`Selected protocol "${protocol}" for reader "${Super.reader.name}"`);
                                resolve()
                            }
                        })
                    }
                })
            })
        } else 
            return Promise.resolve()
    }

    forceResetCardState() {
        return new Promise((resolve, reject) => {
            let Super = this;
            Super.reader.disconnect(Super.reader.SCARD_LEAVE_CARD, function(err) {
                if (err) {
                    console.error(`Error disconnecting the card! The message is: ${err}`);
                    reject(`Error disconnecting the card! The message is: ${err}`)
                } else {
                    Super.initialised = false;
                    Super.reader.connect({ share_mode : Super.reader.SCARD_SHARE_SHARED }, function(err, protocol) {                    
                        if (err) {
                            console.error(`Error connecting to card! The message is: ${err}`);
                            reject(`Error connecting to card! The message is: ${err}`)
                        } else {
                            Super.protocol = protocol
                            console.log(`Selected protocol "${protocol}" for reader "${Super.reader.name}"`);
                            resolve()
                        }
                    })
                }
            })
        })
    }

    selectFIDOApplet() {
        let selectAppleBuffer = Buffer.from([0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00]);

        if(!this.initialised && !this.skipInit)
            this.queue[0].buffersToSent = [selectAppleBuffer].concat(this.queue[0].buffersToSent);
    }

    getNextTransaction() {
        let job = this.queue[0];

        if(job) {
            let sentBuffer    = job.buffersToSent[0];
            job.buffersToSent = job.buffersToSent.slice(1);
            return sentBuffer
        }

        console.log('SET NOT BUSY getNextTransaction')
        this.busy = false;
        return undefined
    }

    dontResetCard() {
        return !!this.queue[0].dontResetCard
    }

    anyTransactionsLeft() {
        let job = this.queue[0];
        return !!(job && job.buffersToSent.length)
    }

    prepareForNextTransaction() {
        this.resetCardState()
            .then(() => {
                this.queue = this.queue.slice(1);
                this.busy  = false;

                if(this.queue.length) {
                    this.proccedWithExchange();
                }
            })
            .catch(() => {
                this.queue = this.queue.slice(1);
                this.busy  = false;

                if(this.queue.length) {
                    this.proccedWithExchange();
                }
            })
    }

    completeTransaction(responseBuffer, requestBuffer) {
        let statusCode = readBE16(new Uint8Array(responseBuffer.slice(responseBuffer.length - 2, responseBuffer.length)))
        let status     = APDU_STATUS_CODES[statusCode];

        console.log('RECEIVED ', status)
        if(status === 'SW_NO_ERROR' && requestBuffer.toString('hex') === '00a4040008a0000006472f000100') {
            this.initialised = true;

            if(!this.anyTransactionsLeft()) {
                this.queue[0].buffersReceived.push(responseBuffer);
                this.succeedJob();
            }
        } else if(status === 'SW_NO_ERROR') {
            if(!this.anyTransactionsLeft()) {
                this.queue[0].buffersReceived.push(responseBuffer);
                this.succeedJob();            
            }
        } else if(status === 'SW_BYTES_REMAINING_00' || (statusCode - 0x6100 > 0 && statusCode - 0x6100 < 0x100)) {
            let Lc = statusCode - 0x6100;
            console.log('Bytes remaining: ', Lc)
            this.queue[0].buffersReceived.push(responseBuffer.slice(0, responseBuffer.length - 2));
            this.queue[0].buffersToSent.push(Buffer.from([requestBuffer[0], 0x0C0, 0x00, 0x00, Lc]));
        } else {
            this.failJob(statusCode, 'Authenticator returned error ' + status);
        }
    }

    proccedWithExchange() {
        this.selectFIDOApplet();
        let requestBuffer = this.getNextTransaction()

        console.log('NFC DATA SENT: ' + requestBuffer.toString('hex'));
        this.reader.transmit(requestBuffer, 65536, this.protocol, (err, responseBuffer) => {
            if (err) {
                this.failJob(0x6F00, `Error while sending buffer: ${err}`);
            } else {
                console.log('NFC DATA RECEIVED: ' + responseBuffer.toString('hex'));
                this.completeTransaction(responseBuffer, requestBuffer);

                if(this.anyTransactionsLeft())
                    this.proccedWithExchange();
            }
        })
    }

    executeCallback(error, response) {
        this.queue[0].callback(error, response)
    }

    succeedJob() {
        this.busy = true;
        this.executeCallback(undefined, this.queue[0].buffersReceived)
        this.prepareForNextTransaction()
    }

    failJob(statusCode, message) {
        this.busy = true;
        this.executeCallback({
            'statusCode': statusCode,
            'statusCodeDef': APDU_STATUS_CODES[statusCode],
            'errorMessage': message
        })

        this.prepareForNextTransaction()
    }

    addJob(buffersToSent, skipInit, dontResetCard, callback) {
        let buffersReceived = [];
        this.queue.push({buffersToSent, buffersReceived, callback, skipInit, dontResetCard});

        if(!this.busy) {
            this.busy = true;
            this.proccedWithExchange()
        }
    }
}

let publicReaders = {};

if(isPrivileged || os.platform() !== 'win32') {
    try {
        let pcsc = pcsclite();
        pcsc.on('reader', function(reader) {
            /* ---- Name resolver ----- */
            if(publicReaders[reader.name]) {
                let allNames      = Object.keys(publicReaders);
                let selectedNames = allNames.filter((item) => item.startsWith(reader.name));
                selectedNames     = selectedNames.sort((a,b) => a > b);
                let numberStr     = selectedNames.pop()
                numberStr         = numberStr.slice(numberStr.length - 3, numberStr.length).replace(/[\(\)]*/g, '')
                number            = parseInt(numberStr) + 1 || 1;

                reader.name = `${reader.name} (${number})`;
            }

            /* ---- Setting up new reader ----- */
            console.log('New reader detected', reader.name);
            publicReaders[reader.name] = new NFCReader(reader)

            /* ----- Ensure correct behaviour ----- */
            reader.on('end', function() {
                console.log('Reader',  this.name, 'removed');
                delete publicReaders[this.name];
            })
        })

        pcsc.on('error', function(err) {
            console.error('PCSC error', err.message);
        })
    } catch(e) {
        publicReaders['ERROR CONNECTING TO NFC READER! TRY CONNECT READER AND REFRESH THE TOOL!'] = {}
    }
} else {
    publicReaders['To test FIDO2 authenticators on Windows, you must be running tools as Administrator! Please close the tools, right click the Icon, and select "Run as Administrator"!'] = {}
}


let getReaderDevice = (deviceInfo) => {
    if(deviceInfo.transport !== 'NFC')
        throw new Error(`Device "${deviceInfo.product}" is not an NFC reader!`);

    let device = publicReaders[deviceInfo.product];
    if(!device)
        throw new Error(`Reader "${deviceInfo.product}" is disconnected!`);

    return device
}


let ensureBuffers = (buffers) => {
    let newBuffers = [];
    for(let buffer of buffers) {
        newBuffers.push(Buffer.from(Array.from(buffer)))
    }

    return newBuffers
}

let ensureUints = (buffers) => {
    let newBuffers = [];
    for(let buffer of buffers) {
        newBuffers.push(new Uint8Array(Array.from(buffer)))
    }

    return newBuffers
}

module.exports = {
    'getAvailableReaders': () => {
        let transport = 'NFC';
        let arrayOfReaders = Object.keys(publicReaders);
        arrayOfReaders = arrayOfReaders.map((product) => {
            return {product, transport}
        })

        return arrayOfReaders
    },

    'getState': (deviceInfo) => {
        let reader = publicReaders[deviceInfo.product];
        if(!reader)
            return 'disconnected';

        return reader.cardInserted ? 'ready' : 'insert card';
    },

    'forceResetCard': (deviceInfo) => {
        let device = getReaderDevice(deviceInfo);

        return device.forceResetCardState(deviceInfo)
    },

    'sendNFCAPDUBuffers': (deviceInfo, buffers, skipInit, dontResetCard) => {
        buffers = ensureBuffers(buffers)
        return new Promise((resolve, reject) => {
            try {
                let outTimer = setTimeout(() => {
                    reject(new Error('Timeout!'));
                }, 10000);

                let device = getReaderDevice(deviceInfo);
                device.addJob(buffers, skipInit, dontResetCard, (error, response) => {
                    clearTimeout(outTimer);

                    if(error) {
                        reject(error)
                        return
                    }

                    response = ensureUints(response)
                    resolve(response)
                })
            } catch(error) {
                console.error(error)
                reject(`Error sending APDU: ${error}`, undefined)
            }
        })
    },

    'sendNFCAPDUBuffer': (deviceInfo, buffer, skipInit, dontResetCard) => {
        buffer = ensureBuffers([buffer])[0];
        return new Promise((resolve, reject) => {
            try {
                let outTimer = setTimeout(() => {
                    reject(new Error('Timeout!'));
                }, 10000);

                let device = getReaderDevice(deviceInfo);
                device.addJob([buffer], skipInit, dontResetCard, (error, response) => {
                    clearTimeout(outTimer);

                    if(error)
                        reject(error)

                    response = ensureUints(response)
                    resolve(response)
                })


            } catch(error) {
                reject(`Error sending APDU: ${error}`, undefined)
            }
        })
    }
}
