/**
 * HID CONSTS
 */
    let CTAPHID_CMD = {
        CTAPHID_PING   : 0x80 | 0x01,
        CTAPHID_MSG    : 0x80 | 0x03,
        CTAPHID_LOCK   : 0x80 | 0x04,
        CTAPHID_INIT   : 0x80 | 0x06,
        CTAPHID_WINK   : 0x80 | 0x08,
        CTAPHID_SYNC   : 0x80 | 0x3c,
        CTAPHID_CBOR   : 0x80 | 0x10,
        CTAPHID_CANCEL : 0x80 | 0x11,
        CTAPHID_ERROR  : 0x80 | 0x3f,
        CTAPHID_KEEPALIVE: 0x80 | 0x3b
    }
    Object.assign(CTAPHID_CMD, inverseDictionary(CTAPHID_CMD))

    let CAPFLAG_WINK  = 0x01;
    let CAPFLAG_LOCK  = 0x02;
    let CAPFLAG_CBOR  = 0x04;
    let CAPFLAG_NMSG  = 0x08;

    let STATUS_PROCESSING = 0x01;
    let STATUS_UPNEEDED   = 0x02;

    let CTAPHID_IF_VERSION = 0x02;

    let CTAPHID_MAX_PACKET_SIZE  = 64;
    let CTAPHID_MAX_PAYLOAD_SIZE = 7609;

    if(window.config && window.config.test && window.config.test.CustomHIDConfigSize) {
        CTAPHID_MAX_PACKET_SIZE = window.config.test.CustomHIDConfigSize;
        console.error("!!!! WARNING! CUSTOME HID PACKET SIZE ENABLED !!!!");
    }

    let CTAPHID_CIDO = [0xff, 0xff, 0xff, 0xff];
    
/**
 * APDU CONSTS
 */
    let dataLenInit = CTAPHID_MAX_PACKET_SIZE - 7;
    let dataLenCont = CTAPHID_MAX_PACKET_SIZE - 5;

/**
 * Takes CID buffer and returns 32bit integer
 * @param  {ArrayBuffer{4}} buffer - CID
 * @return {Int}
 */
let cidToInt = (buffer) => {
    if (buffer.byteLength !== 4)
        throw new Error('CID must be 4 bytes long!');

    return new Uint32Array(buffer.buffer || buffer)[0];
}

/**
 * Takes a HID INIT buffer, and returns a parsed object
 * @param  {ArrayBuffer} buffer - Buffer to parse
 * @return {Object}             - Parsed object
 */
let parseCTAPHIDPacket = (buffer) => {
    let struct = {
        'CID': Array.from(buffer.slice(0, 4)),
        'CMD': buffer[4],
        'BCNT': (buffer[5] << 8) + buffer[6],
    }


    let data = buffer.slice(7);
    switch(struct.CMD) {
        case CTAPHID_CMD.CTAPHID_PING:
            struct.DATA = data;
        break;
        
        case CTAPHID_CMD.CTAPHID_MSG:
            struct.DATA = data;
        break;
        case CTAPHID_CMD.CTAPHID_CBOR:
            struct.DATA = data;
        break;

        case CTAPHID_CMD.CTAPHID_SYNC:
        break;
        
        case CTAPHID_CMD.CTAPHID_INIT:
            struct.NONCE        = Array.from(data.slice(0, 8)),
            struct.NEWCID       = Array.from(data.slice(8, 12)),
            struct.IFVERSION    = data[12],
            struct.MAJORVERSION = data[13],
            struct.MINORVERSION = data[14],
            struct.BUILDNUMBER  = data[15],
            struct.CAPABILITIES = {
                'WINK': !!(data[16] & CAPFLAG_WINK),
                'LOCK': !!(data[16] & CAPFLAG_LOCK),
                'CBOR': !!(data[16] & CAPFLAG_CBOR),
                'NMSG': !!(data[16] & CAPFLAG_NMSG),
                'raw': data[16]
            }
        break;
        
        case CTAPHID_CMD.CTAPHID_ERROR:
            struct.ERRORCODE = data[0];
            struct.ERRORMSG  = CTAP_ERROR_CODES[data[0]];
        break;

        case CTAPHID_CMD.CTAPHID_KEEPALIVE:
            struct.STATUSCODE = data[0];

            if(data[0] === STATUS_PROCESSING)
                struct.STATUSMSG = 'PROCESSING';
            else if(data[0] === STATUS_UPNEEDED)
                struct.STATUSMSG = 'UPNEEDED';
        break;

        case CTAPHID_CMD.CTAPHID_WINK:
            //Return nothing
        break;

        case CTAPHID_CMD.CTAPHID_LOCK:
            //Return nothing
        break;
    }

    return struct
}

/**
 * Takes data, command, and channel ID and generates an array of HID buffers
 * @param  {CTAPHIDCommand} command    - U2FHID command
 * @param  {ArrayBuffer}   data       - Data buffer
 * @param  {ArrayBuffer}   channelid  - (Optional) Channel ID. Defaults to CID9
 * @return {ArrayBuffer[]}            - An array of buffers
 */
let generateRequestFrames = (command, data, channelid) => {
    data = new Uint8Array(data)
    if (data.length > CTAPHID_MAX_PAYLOAD_SIZE)
        return Promise
            .reject(new Error(`Payload is larger than maximum allowed payload size of ${CTAPHID_MAX_PAYLOAD_SIZE} bytes!`));

    let buffers = [];

    let buffer     = new Uint8Array(CTAPHID_MAX_PACKET_SIZE);
    let cid        = channelid || new Uint8Array(CTAPHID_CIDO)

    let lenBuff    = getBigEndianEcoding(new Uint16Array([data.byteLength]));

    buffer.set(cid);          //CID
    buffer.set([command], 4); //CMD
    buffer.set(lenBuff, 5);   //BCNT
    buffer.set(data.slice(0, dataLenInit), 7); //DAT

    buffers.push(buffer)

    let leftOverBuffer = data.slice(dataLenInit)

    for (let i = 0; i < Math.ceil(leftOverBuffer.length / dataLenCont); i++) {
        let bufferDataCont = leftOverBuffer.slice(dataLenCont * i, dataLenCont * (i + 1));

        let contBuffer = new Uint8Array(CTAPHID_MAX_PACKET_SIZE);
        contBuffer.set(cid);                //CID
        contBuffer.set([i], 4);             //SEQ
        contBuffer.set(bufferDataCont, 5);  //DAT

        buffers.push(contBuffer);
    }

    return buffers
}

/**
 * Takes an array of response buffers(INIT and CONT) and merges them into a single INIT frame
 * @param  {ArrayBuffer[]} result - Buffers
 * @return {ArrayBuffer}          - Response Buffer
 */
let processResponseBuffers = (result) => {
    let headBuffer = result[0];
    let dataSize = (headBuffer[5] << 8) + headBuffer[6];
    let CIDHead = new Uint16Array(headBuffer.slice(0, 4).buffer)[0];
    let resultBuffer = new Uint8Array(7 + dataSize);
    resultBuffer.set(headBuffer.slice(0, 7 + dataSize));

    result = result.slice(1); // Slicing Init Packet off
    let contBufferSize = dataSize - dataLenInit; // Counting leftover data length

    for (let i = 0; i < result.length; i++) {
        let buffer = result[i];
        let CID    = new Uint16Array(buffer.slice(0, 4).buffer)[0];
        let SEQ    = buffer[4];
        let DAT    = buffer.slice(5);

        if (CID !== CIDHead)
            throw new Error('Init packet and continuation packet CID\'s don\'t match!');

        if (SEQ !== i)
            throw new Error('Sequence out of order!');

        if ((contBufferSize - (i + 1) * dataLenCont) < 0) {
            DAT = DAT.slice(0, contBufferSize - i * dataLenCont)
        }

        resultBuffer.set(DAT, CTAPHID_MAX_PACKET_SIZE + dataLenCont * i);
    }

    return resultBuffer
}

/* ----- Transport commands ----- */

/**
 * Takes data, command, and sends it to the device
 * @param  {CTAPHIDCommand} command  - CTAPHID command
 * @param  {ArrayBuffer}   data       - Data buffer
 * @param  {ArrayBuffer}   channelid  - (Optional) Channel ID. Defaults to CID9
 * @return {Promise<ArrayBuffer>}     - Returns an ArrayBuffer response
 */
let sendCTAPHIDCommand = (command, data, channelid) => {
    let deviceInfo = getDeviceInfo();
    let buffers    = generateRequestFrames(command, data, channelid);
    return window.navigator.fido.fido2.hid.sendHIDBuffers(deviceInfo, buffers)
        .then((buffers) => {
            return processResponseBuffers(buffers)
        })
}

/**
 * Takes data, command, and sends it to the device
 * @param  {CTAPHIDCommand} command  - CTAPHID command
 * @param  {ArrayBuffer}   data       - Data buffer
 * @param  {ArrayBuffer}   channelid  - (Optional) Channel ID. Defaults to CID9
 * @return {Promise<ArrayBuffer>}     - Returns an ArrayBuffer response
 */
let sendCTAPHIDCommandSync = (command, data, channelid) => {
    let deviceInfo = getDeviceInfo();
    let buffers    = generateRequestFrames(command, data, channelid);
    window.navigator.fido.fido2.hid.sendHIDBuffersSync(deviceInfo, buffers)
}

/**
 * Sends CTAPHID_INIT command and returns new CID
 * @return {ArrayBuffer} - New assigned CID
 */
let sendCTAPHID_INITCommand = () => {
    let nonce = generateRandomBuffer(8);

    return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_INIT, nonce)
        .then((result) => {
            let response = parseCTAPHIDPacket(result);

            if (response.CMD === CTAPHID_CMD.CTAPHID_ERROR)
                throw new Error(`Error sending CTAPHID_INIT: ${response.ERRORMSG}`);

            return response
        })
}

/**
 * Send CTAPHID_CBOR command
 * @param  {Buffer} requestBuffer - request buffer
 * @return {Promise<CTAP2Response>}
 */
let sendCTAPHID_CBORCommand = (requestBuffer) => {
    return sendCTAPHID_INITCommand()
        .then((initResponse) => {
            return sendCTAPHIDCommand(CTAPHID_CMD.CTAPHID_CBOR, requestBuffer, initResponse.NEWCID)
        })
        .then((result) => {
            let response = parseCTAPHIDPacket(result);

            if(response.ERRORCODE !== undefined)
                throw new Error(`Error: Authenticator returned an HID error ${response.ERRORMSG}(${response.ERRORCODE})`);

            return response.DATA
        })
}
