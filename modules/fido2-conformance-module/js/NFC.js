/**
 * HID CONSTS
 */
    let U2FHID_IF_VERSION = 0x02;

    let U2FHID_MAX_PACKET_SIZE  = 64;
    let U2FHID_MAX_PAYLOAD_SIZE = 7609;

    let U2FHID_CIDO = [0xff, 0xff, 0xff, 0xff];
    
    let U2FHID_ERROR_CODES = {
        0x00 : 'ERR_NONE',
        0x01 : 'ERR_INVALID_CMD',
        0x02 : 'ERR_INVALID_PAR',
        0x03 : 'ERR_INVALID_LEN',
        0x04 : 'ERR_INVALID_SEQ',
        0x05 : 'ERR_MSG_TIMEOUT',
        0x06 : 'ERR_CHANNEL_BUSY',
        0x0a : 'ERR_LOCK_REQUIRED',
        0x0b : 'ERR_INVALID_CID',
        0x7f : 'ERR_OTHER'
    }
    Object.assign(U2FHID_ERROR_CODES, inverseDictionary(U2FHID_ERROR_CODES))

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
    Object.assign(APDU_STATUS_CODES, inverseDictionary(APDU_STATUS_CODES))

/**
 * APDU CONSTS
 */
    let NFCCTAP_MSG = 0x80;
    let NFCCTAP_MSG_CHAINED = 0x90;

/**
 * Generates extended APDU frame
 * @param  {Number} CLA       - APDU class
 * @param  {Number} INS       - APDU instruction
 * @param  {Number} P1        - APDU parameter one
 * @param  {Number} P2        - APDU parameter two
 * @param  {ArrayBuffer} data - Data buffer
 * @return {ArrayBuffer}      - APDU framed data buffer
 */
let frameAPDUExtended = (CLA, INS, P1, P2, data) => {
    let length = 4;

    if(data)
        length += 3 + data.length + 2;


    let buffer = new Uint8Array(length);

    /* APDU-C HEADER */
    buffer[0] = CLA;  // CLA
    buffer[1] = INS;  // INS
    buffer[2] = P1;   // P1
    buffer[3] = P2;   // P2

    /* APDU-C BODY */
    let offset = 4;
    if (data) {
        buffer[offset] = 0;

        buffer.set(getBigEndianEcoding(new Uint16Array([data.length])), 5); // LC2, LC3 (LSB)
        buffer.set(data, 7);
        offset = 7 + data.length;

        buffer[offset + 1] = 0x00;
        buffer[offset + 2] = 0x00;
    }

    return buffer
}

/**
 * Generates extended CTAP APDU frame
 * @param  {ArrayBuffer} buffer - command buffer
 * @return {ArrayBuffer}        - APDU command frame
 */
let generateExtendedAPDUCTAP2Frame = (buffer) => {
    return frameAPDUExtended(NFCCTAP_MSG, 0x10, 0x00, 0x00, buffer);
}


/**
 * Generates short APDU frame
 * @param  {Number} CLA       - APDU class
 * @param  {Number} INS       - APDU instruction
 * @param  {Number} P1        - APDU parameter one
 * @param  {Number} P2        - APDU parameter two
 * @param  {ArrayBuffer} data - Data buffer
 * @return {ArrayBuffer}      - APDU framed data buffer
 */
let frameAPDUShort = (CLA, INS, P1, P2, data) => {
    let length = 4;

    if(data) {
        if(data.length > 255)
            throw new Error('Short APDU supports only max of 255 bytes!');

        length += 1 + data.length + 1;

        if(!!(CLA & 0x10)) //APDU Chaining CLA bit 5 is set
            length -= 1;
    }


    let buffer = new Uint8Array(length);

    /* APDU-C HEADER */
    buffer[0] = CLA;  // CLA
    buffer[1] = INS;  // INS
    buffer[2] = P1;   // P1
    buffer[3] = P2;   // P2

    /* APDU-C BODY */
    let offset = 4;
    if (data) {
        buffer[offset] = new Uint8Array([data.length]);
        buffer.set(data, 5);

        if(!(CLA & 0x10)) {//APDU Chaining CLA bit 5 is set
            offset = 5 + data.length;
            buffer[offset + 1] = 0x00;
        }
    }

    return buffer
}

/**
 * Generates short CTAP APDU frame
 * @param  {ArrayBuffer} ctapBuffer - command buffer
 * @return {ArrayBuffer}            - APDU command frames
 */
let generateShortAPDUCTAP2Frames = (ctapBuffer) => {
    let frames = [];
    let cblen  = ctapBuffer.length;

    for(let i = 0; i < Math.ceil(cblen / 240); i++) {
        let CLA = NFCCTAP_MSG;

        let slice  = ctapBuffer.slice(i * 240, (i+1) * 240);

        if((i+1) * 240 < cblen)
            CLA += 0x10;

        let frame = frameAPDUShort(CLA, 0x10, 0x00, 0x00, slice)

        frames.push(frame);
    }

    return frames
}

/**
 * Generates short CTAP APDU frame that have random size
 * @param  {ArrayBuffer} ctapBuffer - command buffer
 * @return {ArrayBuffer}            - APDU command frames
 */
let generateRandomlySizedShortAPDUCTAP2Frames = (ctapBuffer) => {
    let frames = [];
    let cblen  = ctapBuffer.length;

    for(let i = 0; i < Math.ceil(cblen / 240); i++) {
        let CLA = NFCCTAP_MSG;

        let slice  = ctapBuffer.slice(i * 240, (i+1) * 240);

        if((i+1) * 240 < cblen)
            CLA += 0x10;

        let frame = frameAPDUShort(CLA, 0x10, 0x00, 0x00, slice)

        frames.push(frame);
    }

    return frames
}

/* ----- Transport commands ----- */

/**
 * Sends CTAPHID_INIT command and returns new CID
 * @return {ArrayBuffer} - New assigned CID
 */
let sendCTAPNFC_INITCommand = () => {
    let appletSelectionCommand = new Uint8Array([0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    return navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), [appletSelectionCommand], true)
        .then((response) => {
            if(hex.encode(response[0]) !== '5532465f5632')
                throw new Error('Unable to select FIDO applet!');

            return
        })
}

/**
 * Send CTAP_CBOR command wrapped in Short APDU chain
 * @param  {Buffer} requestBuffer - request buffer
 * @return {Promise<CTAP2Response>}
 */
let sendShortCTAPNFC_CBORCommand = (requestBuffer, options) => {
    options = options || {};
    let frames = generateShortAPDUCTAP2Frames(requestBuffer);
    return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames, options.noInit, options.dontResetCard)
        .then((result) => {
            let base = new Uint8Array();

            for(let buff of result)
                base = mergeArrayBuffers(base, buff)

            base = base.slice(0, base.length - 2)

            return base
        })
}

/**
 * Send CTAP_CBOR command wrapped in Extended APDU
 * @param  {Buffer} requestBuffer - request buffer
 * @return {Promise<CTAP2Response>}
 */
let sendExtendedCTAPNFC_CBORCommand = (requestBuffer, options) => {
    options = options || {};
    let frames = [generateExtendedAPDUCTAP2Frame(requestBuffer)];
    return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), frames, options.noInit, options.dontResetCard)
        .then((result) => {
            let base = new Uint8Array();

            for(let buff of result)
                base = mergeArrayBuffers(base, buff)

            base = base.slice(0, base.length - 2)

            return base
        })
}
