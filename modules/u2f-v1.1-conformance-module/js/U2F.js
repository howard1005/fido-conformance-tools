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

/**
 * APDU CONSTS
 */
    let P256_SCALAR_SIZE = 32; // nistp256 in bytes
    let P256_POINT_SIZE  = ((P256_SCALAR_SIZE * 2) + 1)

    let MAX_ECDSA_SIG_SIZE = 72;   // asn1 DER format
    let MAX_KH_SIZE        = 128;   // key handle
    let MAX_CERT_SIZE      = 2048; // attestation certificate

    let UNCOMPRESSED_POINT    = 0x04;

    let U2F_INS_REGISTER      = 0x01;
    let U2F_INS_AUTHENTICATE  = 0x02;
    let U2F_INS_VERSION       = 0x03;

    let U2F_REGISTER_ID       = 0x05;
    let U2F_REGISTER_HASH_ID  = 0x00;

    let U2F_AUTH_ENFORCE      = 0x03; // Require user presence
    let U2F_AUTH_CHECK_ONLY   = 0x07; // Test but do not consume
    // let U2F_AUTH_DONT_ENFORCE = 0x08;

    let U2F_TOUCHED              = 0x01;
    let U2F_ALTERNATE_INTERFACE  = 0x02;

    let U2F_APPID_SIZE = 32;
    let U2F_NONCE_SIZE = 32;

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

    let ISO_APDU_CHAINED = 0xC0;

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
    let length = 7;

    if(data && data.length)
        length += 2 + data.length;

    let buffer = new Uint8Array(length);

    /* APDU-C HEADER */
    buffer[0] = CLA;  // CLA
    buffer[1] = INS;  // INS
    buffer[2] = P1;   // P1
    buffer[3] = P2;   // P2

    /* APDU-C BODY */
    let offset = 4;
    if (data && data.length) {
        buffer[offset] = 0;

        buffer.set(getBigEndianEcoding(new Uint16Array([data.length])), 5); // LC2, LC3 (LSB)
        buffer.set(data, 7);
        offset = 7 + data.length;
    } else {
        buffer[offset] = 0x00;
    }

    buffer[offset + 1] = 0x00;
    buffer[offset + 2] = 0x00;

    return buffer
}

/**
 * Generates extended CTAP APDU frame
 * @param  {ArrayBuffer} buffer - command buffer
 * @return {ArrayBuffer}        - APDU command frame
 */
let generateExtendedAPDUCTAP1Frame = (INS, buffer, P1, CLA) => {
    if(!CLA)
        CLA = 0x00;

    return frameAPDUExtended(CLA, INS, P1, 0, buffer);
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

    if(data && data.length) {
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
    if (data && data.length) {
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
 * @param  {Number} INS              - APDU instruction
 * @param  {BufferSource} ctapBuffer - command buffer
 * @param  {Number} P1               - APDU P1
 * @param  {Number} CLA              - APDU class
 * @return {BufferSource}            - APDU command frames
 */
let generateShortAPDUCTAP1Frames = (INS, ctapBuffer, P1, CLA) => {
    if(!CLA)
        CLA = 0x00;

    let frames = [];
    let cblen  = ctapBuffer.length;

    for(let i = 0; i < Math.ceil(cblen / 240); i++) {
        let PROBABLY_INS = INS;
        let PROBABLY_P1  = P1;

        let slice = ctapBuffer.slice(i * 240, (i+1) * 240);

        if((i+1) * 240 < cblen) {
            PROBABLY_INS += ISO_APDU_CHAINED;
            PROBABLY_P1  += 0x00;
        }

        let frame = frameAPDUShort(CLA, PROBABLY_INS, PROBABLY_P1, 0, slice)

        frames.push(frame);
    }

    return frames
}

/**
 * Generates short CTAP APDU frame that have random size
 * @param  {ArrayBuffer} ctapBuffer - command buffer
 * @return {ArrayBuffer}            - APDU command frames
 */
let generateRandomlySizedShortAPDUCTAP1Frames = (INS, ctapBuffer, P1) => {
    let frames = [];
    let cblen  = ctapBuffer.length;

    for(let i = 0; i < Math.ceil(cblen / 240); i++) {
        let PROBABLY_INS = INS;
        let PROBABLY_P1  = P1;

        let slice  = ctapBuffer.slice(i * 240, (i+1) * 240);

        if((i+1) * 240 < cblen) {
            PROBABLY_INS += ISO_APDU_CHAINED;
            PROBABLY_P1  += 0x00;
        }

        let frame = frameAPDUShort(0, PROBABLY_INS, PROBABLY_P1, 0, slice)

        frames.push(frame);
    }

    return frames
}

/**
 * Decode initial bytes of buffer as ASN and return the length of the encoded structure.
 * See http://en.wikipedia.org/wiki/X.690
 * Only SEQUENCE top-level identifier is supported (which covers all certs luckily)
 * Stolen from https://github.com/ashtuchkin/u2f/blob/master/index.js#L62
 * @param  {ArrayBuffer} buf - ASN1 buffer
 * @return {Number}          - The length of the found ASN1 structure
 */
let asnLen = (buf) => {
    if (buf.length < 2 || buf[0] != 0x30)
        throw new Error("Invalid data: Not a SEQUENCE ASN/DER structure");

    var len = buf[1];
    if (len & 0x80) { // long form
        var bytesCnt = len & 0x7F;
        if (buf.length < 2+bytesCnt)
            throw new Error("Invalid data: ASN structure not fully represented");
        len = 0;
        for (var i = 0; i < bytesCnt; i++)
            len = len*0x100 + buf[2+i];
        len += bytesCnt; // add bytes for length itself.
    }

    return len + 2; // add 2 initial bytes: type and length.
}


let generateGoodAPDURegisterFrame = () => {
    let challengeHash = generateRandomBuffer(32);
    let appIDHash     = generateRandomBuffer(32);

    return generateAPDURegisterFrame(challengeHash, appIDHash);
}

/**
 * Generates APDU register frame
 * @param  {ArrayBuffer} ChallengeHash - SHA-256 hash of the challenge
 * @param  {ArrayBuffer} AppIDHash     - SHA-256 hash of the appID
 * @return {ArrayBuffer}               - APDU Register command frame
 */
let generateAPDURegisterFrame = (ChallengeHash, AppIDHash) => {
    return mergeArrayBuffers(ChallengeHash, AppIDHash);
}

/**
 * Generates APDU sign frame
 * @param  {ArrayBuffer} ChallengeHash - SHA-256 hash of the challenge
 * @param  {ArrayBuffer} AppIDHash     - SHA-256 hash of the appID
 * @param  {ArrayBuffer} KeyHandle     - KeyHandle buffer
 * @return {ArrayBuffer}               - Register command frame
 */
let generateAPDUSignFrame = (ChallengeHash, AppIDHash, KeyHandle) => {
    let KHLengthBuffer = new Uint8Array([KeyHandle.length]);
    let request        = mergeArrayBuffers(ChallengeHash, AppIDHash, KHLengthBuffer, KeyHandle);

    return request
}

/**
 * Decodes APDU response
 * @param  {ArrayBuffer} buffer
 * @return {Object}
 */
let parseAPDUResponse = (buffer) => {
    let SW12buff = new Uint8Array(buffer.slice(buffer.length - 2, buffer.length));
    let SW12 = readBE16(SW12buff);
    let DATA = buffer.slice(0, buffer.length - 2);

    return {
        SW12, DATA
    }
}

/**
 * Decodes APDU register response
 * @param  {ArrayBuffer} buffer - response DATA buffer
 * @return {Object}             - APDU register response struct
 */
let parseCTAP1RegistrationResponse = (buffer) => {
    let RESERVE    = buffer[0];
    buffer         = buffer.slice(1);

    let PUBKEY     = buffer.slice(0, 65);
    buffer         = buffer.slice(65);

    let KHLength   = buffer[0];
    buffer         = buffer.slice(1);

    let KEYHANDLE  = buffer.slice(0, KHLength);
    buffer         = buffer.slice(KHLength);

    let CertASNLen = asnLen(buffer);
    let CERT       = buffer.slice(0, CertASNLen);
    buffer         = buffer.slice(CertASNLen);

    let SignASNLen = asnLen(buffer);
    let SIGN       = buffer.slice(0, SignASNLen);
    buffer         = buffer.slice(SignASNLen);

    if (buffer.length) {
        throw new Error(`Error: U2F Registration response has extra bytes! ${buffer}`);
    }

    return {
        RESERVE, PUBKEY, KEYHANDLE, CERT, SIGN
    }
}

/**
 * Decodes APDU sign response
 * @param  {ArrayBuffer} buffer - response DATA buffer
 * @return {Object}             - APDU sign response struct
 */
let parseCTAP1SignResponse = (buffer) => {
    let USERPRESENCERAW = buffer.slice(0, 1);
    let USERPRESENCE    = buffer[0];
    let COUNTERBuf      = buffer.slice(1, 5);
    let COUNTER         = readBE32(COUNTERBuf);
    let SIGN            = buffer.slice(5);
    let UP              = !!(USERPRESENCERAW[0] & 0x01); // Test of User Presence

    return {
        UP, USERPRESENCERAW, COUNTERBuf, COUNTER, SIGN
    }
}

/**
 * Verifies APDU registration response assertion
 * @param  {ArrayBuffer} ChallengeHash - SHA-256 hash of the challenge
 * @param  {ArrayBuffer} AppIDHash     - SHA-256 hash of the response
 * @param  {Object} APDURegResponse    - APDU registration response struct
 * @return {Boolean}                   - True/False
 */
let verifyRegistrationResponse = (ChallengeHash, AppIDHash, APDURegResponse) => {
    if(ChallengeHash.length !== 32)
        throw new Error('ChallengeHash MUST be 32byte long SHA-256 hash!');

    if(AppIDHash.length !== 32)
        throw new Error('AppIDHash MUST be 32byte long SHA-256 hash!');

    let RFU = new Uint8Array([0x00]);

    let SignatureDataBuffer = mergeArrayBuffers(RFU, AppIDHash, ChallengeHash, APDURegResponse.KEYHANDLE, APDURegResponse.PUBKEY);
    let CertPEMString       = ASN1toPEM(APDURegResponse.CERT);

    return window.navigator.fido.fido2.crypto.verifySignature(CertPEMString, APDURegResponse.SIGN, SignatureDataBuffer);
}

/**
 * Verifies APDU sign response assertion
 * @param  {ArrayBuffer} ChallengeHash - SHA-256 hash of the challenge
 * @param  {ArrayBuffer} AppIDHash     - SHA-256 hash of the response
 * @param  {ArrayBuffer} PubKey        - Public key buffer
 * @param  {Object} APDUSignResponse   - APDU registration response struct
 * @return {Boolean}                   - True/False
 */
let verifySignResponse = (ChallengeHash, AppIDHash, PubKey, APDUSignResponse) => {
    if(ChallengeHash.length !== 32)
        throw new Error('ChallengeHash MUST be 32byte long SHA-256 hash!');

    if(AppIDHash.length !== 32)
        throw new Error('AppIDHash MUST be 32byte long SHA-256 hash!');

    let SignatureDataBuffer = mergeArrayBuffers(AppIDHash, APDUSignResponse.USERPRESENCERAW, APDUSignResponse.COUNTERBuf, ChallengeHash);
    let SignatureBaseHash   = navigator.fido.fido2.crypto.hash('sha256', SignatureDataBuffer)

    return window.navigator.fido.fido2.crypto.verifyECDSASignature('p256', PubKey, APDUSignResponse.SIGN, SignatureBaseHash);
}

/**
 * Generate APDU request frame depending on the transport
 * @param  {Number} INS           - APDU instruction
 * @param  {Buffer} requestBuffer - request buffer
 * @param  {Object} options       - options for call
 * @return {Array<Buffer>}        - array of request buffer frames
 */
let generateRequestFrames = (INS, requestBuffer, options) => {
    let deviceInfo   = getDeviceInfo();
    let PROBABLY_P1  = undefined;
    let PROBABLY_CLA = undefined;

    if(options && INS === U2F_INS_AUTHENTICATE) {
        if(options.enforceUP)
            PROBABLY_P1 = U2F_AUTH_ENFORCE;
        else if(options.checkOnly)
            PROBABLY_P1 = U2F_AUTH_CHECK_ONLY;
        // else if(options.dontEnforceUP) // U2F
        //     PROBABLY_P1 = U2F_AUTH_DONT_ENFORCE;
    }
    PROBABLY_P1 = PROBABLY_P1 || 0x00;

    if(options && options.customCLA)
        PROBABLY_CLA = options.customCLA;

    if(!requestBuffer || !requestBuffer.length)
        return [frameAPDUShort(0x00, INS, PROBABLY_P1, 0x00, new Uint8Array())]

    if(deviceInfo.transport === 'HID' || deviceInfo.transport === 'BLE' || (options  && options.requireExtended))
        return [generateExtendedAPDUCTAP1Frame(INS, requestBuffer, PROBABLY_P1, PROBABLY_CLA)];
    else
        return generateShortAPDUCTAP1Frames(INS, requestBuffer, PROBABLY_P1, PROBABLY_CLA);
}

/**
 * Send CTAP_MSG command
 * @param  {Buffer} requestBuffer - request buffer
 * @param  {Object} options - options for call
 * @return {Promise<ctap1Response>}
 */
let sendCTAP_MSG = (cmd, requestBuffer, options) => {
    let deviceInfo    = getDeviceInfo();
    let requestFrames = generateRequestFrames(cmd, requestBuffer, options);

    let transportPromise = undefined;
    if(deviceInfo.transport === 'HID')
        transportPromise = sendCTAPHID_MSGCommand(requestFrames[0], options);
    else if (deviceInfo.transport === 'NFC')
        transportPromise = sendCTAPNFC_MSGCommand(requestFrames, options);
    else if(deviceInfo.transport === 'BLE')
        transportPromise = sendCTAPBLE_MSGCommand(requestFrames[0]);
    else
        throw new Error(`"${deviceInfo.transport}" is an unsupported transport!`);

    return transportPromise
        .then((result) => {
            let authrResponse  = parseAPDUResponse(result);
            let statusCode     = authrResponse.SW12;
            let responseStruct = undefined;
            let responseRaw    = undefined;

            if(statusCode === APDU_STATUS_CODES.SW_NO_ERROR) {
                responseRaw = authrResponse.DATA;
                if(requestFrames[0][1] === U2F_INS_REGISTER)
                    responseStruct = parseCTAP1RegistrationResponse(authrResponse.DATA)
                else if(requestFrames[0][1] === U2F_INS_AUTHENTICATE)
                    responseStruct = parseCTAP1SignResponse(authrResponse.DATA)
                else if(requestFrames[0][1] === U2F_INS_VERSION)
                    responseStruct = {'version': arrayBufferToString(authrResponse.DATA)}
            }

            return {
                statusCode, responseStruct, responseRaw
            }
        })
}

let sendValidCTAP_MSG = (cmd, requestBuffer, options) => {
    return sendCTAP_MSG(cmd, requestBuffer, options)
        .then((ctap1Response) => {
            if(ctap1Response.statusCode !== APDU_STATUS_CODES.SW_NO_ERROR)
                throw new Error(`Expected authenticator to succeed with SW_NO_ERROR(${APDU_STATUS_CODES.SW_NO_ERROR.toString(16)}). Got ${APDU_STATUS_CODES[ctap1Response.statusCode]}(${ctap1Response.statusCode})`);

            return ctap1Response
        })
}

let calculateSubjectKeyIdentifier = (certBuffer) => {
    if(!certBuffer)
        throw new Error('calculateSubjectKeyIdentifier: certBuffer is undefined!');

    let cert = new jsrsasign.X509();
    cert.readCertPEM(ASN1toPEM(certBuffer));

    let subjectPubKeyBuffer     = hex.decode(cert.getPublicKey().pubKeyHex);
    let subjectPubKeyHashBuffer = navigator.fido.fido2.crypto.hash('sha1', subjectPubKeyBuffer);

    return hex.encode(subjectPubKeyHashBuffer)
}
