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

var CTAP_ERROR_CODES = {
    /* Indicates successful response. */
    0x00 : 'CTAP1_ERR_SUCCESS',
    /* The command is not a valid CTAP command. */
    0x01 : 'CTAP1_ERR_INVALID_COMMAND',
    /* The command included an invalid parameter. */
    0x02 : 'CTAP1_ERR_INVALID_PARAMETER',
    /* Invalid message or item length. */
    0x03 : 'CTAP1_ERR_INVALID_LENGTH',
    /* Invalid message sequencing. */
    0x04 : 'CTAP1_ERR_INVALID_SEQ',
    /* Message timed out. */
    0x05 : 'CTAP1_ERR_TIMEOUT',
    /* Channel busy. */
    0x06 : 'CTAP1_ERR_CHANNEL_BUSY',
    /* Command requires channel lock. */
    0x0A : 'CTAP1_ERR_LOCK_REQUIRED',
    /* Command not allowed on this cid. */
    0x0B : 'CTAP1_ERR_INVALID_CHANNEL',
    /* Invalid/unexpected CBOR error. */
    0x11 : 'CTAP2_ERR_CBOR_UNEXPECTED_TYPE',
    /* Error when parsing CBOR. */
    0x12 : 'CTAP2_ERR_INVALID_CBOR',
    /* Missing non-optional parameter. */
    0x14 : 'CTAP2_ERR_MISSING_PARAMETER',
    /* Limit for number of items exceeded. */
    0x15 : 'CTAP2_ERR_LIMIT_EXCEEDED',
    /* Unsupported extension. */
    0x16 : 'CTAP2_ERR_UNSUPPORTED_EXTENSION',
    /* Valid credential found in the exclude list. */
    0x19 : 'CTAP2_ERR_CREDENTIAL_EXCLUDED',
    /* Processing (Lengthy operation is in progress). */
    0x21 : 'CTAP2_ERR_PROCESSING',
    /* Credential not valid for the authenticator. */
    0x22 : 'CTAP2_ERR_INVALID_CREDENTIAL',
    /* Authentication is waiting for user interaction. */
    0x23 : 'CTAP2_ERR_USER_ACTION_PENDING',
    /* Processing, lengthy operation is in progress. */
    0x24 : 'CTAP2_ERR_OPERATION_PENDING',
    /* No request is pending. */
    0x25 : 'CTAP2_ERR_NO_OPERATIONS',
    /* Authenticator does not support requested algorithm. */
    0x26 : 'CTAP2_ERR_UNSUPPORTED_ALGORITHM',
    /* Not authorized for requested operation. */
    0x27 : 'CTAP2_ERR_OPERATION_DENIED',
    /* Internal key storage is full. */
    0x28 : 'CTAP2_ERR_KEY_STORE_FULL',
    /* Authenticator cannot cancel as it is not busy. */
    0x29 : 'CTAP2_ERR_NOT_BUSY',
    /* No outstanding operations. */
    0x2A : 'CTAP2_ERR_NO_OPERATION_PENDING',
    /* Unsupported option. */
    0x2B : 'CTAP2_ERR_UNSUPPORTED_OPTION',
    /* Not a valid option for current operation. */
    0x2C : 'CTAP2_ERR_INVALID_OPTION',
    /* Pending keep alive was cancelled. */
    0x2D : 'CTAP2_ERR_KEEPALIVE_CANCEL',
    /* No valid credentials provided. */
    0x2E : 'CTAP2_ERR_NO_CREDENTIALS',
    /* Timeout waiting for user interaction. */
    0x2F : 'CTAP2_ERR_USER_ACTION_TIMEOUT',
    /* Continuation command, such as, authenticatorGetNextAssertion not allowed. */
    0x30 : 'CTAP2_ERR_NOT_ALLOWED',
    /* PIN Invalid. */
    0x31 : 'CTAP2_ERR_PIN_INVALID',
    /* PIN Blocked. */
    0x32 : 'CTAP2_ERR_PIN_BLOCKED',
    /* PIN authentication,pinAuth, verification failed. */
    0x33 : 'CTAP2_ERR_PIN_AUTH_INVALID',
    /* PIN authentication,pinAuth, blocked. Requires power recycle to reset. */
    0x34 : 'CTAP2_ERR_PIN_AUTH_BLOCKED',
    /* No PIN has been set. */
    0x35 : 'CTAP2_ERR_PIN_NOT_SET',
    /* PIN is required for the selected operation. */
    0x36 : 'CTAP2_ERR_PIN_REQUIRED',
    /* PIN policy violation. Currently only enforces minimum length. */
    0x37 : 'CTAP2_ERR_PIN_POLICY_VIOLATION',
    /* pinToken expired on authenticator. */
    0x38 : 'CTAP2_ERR_PIN_TOKEN_EXPIRED',
    /* Authenticator cannot handle this request due to memory constraints. */
    0x39 : 'CTAP2_ERR_REQUEST_TOO_LARGE',
    /* The current operation has timed out. */
    0x3A : 'CTAP2_ERR_ACTION_TIMEOUT',
    /* User presence is required for the requested operation. */
    0x3B : 'CTAP2_ERR_UP_REQUIRED',
    /* Other unspecified error. */
    0x7F : 'CTAP1_ERR_OTHER',
    /* CTAP 2 spec last error. */
    0xDF : 'CTAP2_ERR_SPEC_LAST',
    /* Extension specific error. */
    0xE0 : 'CTAP2_ERR_EXTENSION_FIRST',
    /* Extension specific error. */
    0xEF : 'CTAP2_ERR_EXTENSION_LAST',
    /* Vendor specific error. */
    0xF0 : 'CTAP2_ERR_VENDOR_FIRST',
    /* Vendor specific error. */
    0xFF : 'CTAP2_ERR_VENDOR_LAST'
}
Object.assign(CTAP_ERROR_CODES, inverseDictionary(CTAP_ERROR_CODES))

var MakeCredentialsRespKeys = {
    'fmt'     : 0x01,
    'authData': 0x02,
    'attStmt' : 0x03
}

var MakeCredentialsReqKeys = {
    'clientDataHash'  : 0x01,
    'rp'              : 0x02,
    'user'            : 0x03,
    'pubKeyCredParams': 0x04,
    'excludeList'     : 0x05,
    'extensions'      : 0x06,
    'options'         : 0x07,
    'pinAuth'         : 0x08,
    'pinProtocol'     : 0x09
}

var GetAssertionRespKeys = {
    'credential': 0x01,
    'authData'  : 0x02,
    'signature' : 0x03,
    'user'      : 0x04,
    'numberOfCredentials': 0x05
}

var GetInfoRespKeys = {
    'versions'    : 0x01,
    'extensions'  : 0x02,
    'aaguid'      : 0x03,
    'options'     : 0x04,
    'maxMsgSize'  : 0x05,
    'pinProtocols': 0x06
}

var ClientPinRespKeys = {
    'keyAgreement': 0x01,
    'pinToken'    : 0x02,
    'retries'     : 0x03
}

var CTAP2COMMANDS = {
    'authenticatorMakeCredential'  : 0x01,
    'authenticatorGetAssertion'    : 0x02,
    'authenticatorGetInfo'         : 0x04,
    'authenticatorClientPIN'       : 0x06,
    'authenticatorReset'           : 0x07,
    'authenticatorGetNextAssertion': 0x08
}

var ClientPinSubCommands = {
    'getRetries': 0x01,
    'getKeyAgreement': 0x02,
    'setPIN': 0x03,
    'changePIN': 0x04,
    'getPINToken': 0x05
}

var ClientPinReqKeys = {
    'pinProtocol'  : 0x01,
    'subCommand'   : 0x02,
    'keyAgreement' : 0x03,
    'pinAuth'      : 0x04,
    'newPinEnc'    : 0x05,
    'pinHashEnc'   : 0x06
}

/**
 * Estableshes pinAuth key agreement
 * @return {Promise<Buffer>} - 32 byte secret key
 */
var establishKeyAgreement = () => {
    let commandBuffer = generateClientPin_GetKeyAgreement();

    return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
    .then((ctap2Response) => {
        if(ctap2Response.statusCode !== CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)
            throw new Error(`For KeyAgreement expected authenticator to succeed with CTAP1_ERR_SUCCESS(${CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`);

        let cborResponse       = ctap2Response.cborResponse;
        let cborResponseStruct = ctap2Response.cborResponseStruct;

        let keyStruct = cborResponse[ClientPinRespKeys.keyAgreement];
        let keyBuffer = COSEECDHAtoPKCS(keyStruct);

        let platformPrivateKey = window.navigator.fido.fido2.crypto.generateP256DHKeys().private;
        let platformPublicKey  = window.navigator.fido.fido2.crypto.deriveP256DHPublicKey(platformPrivateKey)
        
        let sharedSecretPKXCoefficient = window.navigator.fido.fido2.crypto.deriveP256DHSecretsXCoefficient(platformPrivateKey, keyBuffer);
        let sharedSecret = window.navigator.fido.fido2.crypto.hash('sha256', sharedSecretPKXCoefficient);

        let platPKXCoeff = platformPublicKey.slice(1,33);
        let platPKYCoeff = platformPublicKey.slice(33);
        let keyAgreement = {
             '1': 2,
            '-1': 1,
            '3': -25,
            '-2': platPKXCoeff,
            '-3': platPKYCoeff
        }

        return { sharedSecret, keyAgreement }
    })
}

/**
 * Sets new pincode
 * @param  {String} pincode
 * @return {Promise}
 */
var setNewPincode = (pincode) => {
    let keyAgreementCommandBuffer = generateClientPin_GetKeyAgreement();
    return sendValidCTAP_CBOR(keyAgreementCommandBuffer, {'dontResetCard': true})
        .then((response) => {
            let cborResponse       = response.cborResponse;
            let cborResponseStruct = response.cborResponseStruct;

            let keyStruct = cborResponse[ClientPinRespKeys.keyAgreement];
            let keyBuffer = COSEECDHAtoPKCS(keyStruct);

            let platformPrivateKey = window.navigator.fido.fido2.crypto.generateP256DHKeys().private;
            let platformPublicKey  = window.navigator.fido.fido2.crypto.deriveP256DHPublicKey(platformPrivateKey)
            
            let sharedSecretPKXCoefficient = window.navigator.fido.fido2.crypto.deriveP256DHSecretsXCoefficient(platformPrivateKey, keyBuffer);
            let sharedSecret = window.navigator.fido.fido2.crypto.hash('sha256', sharedSecretPKXCoefficient);

            let encryptionBuffer = generateZeroBuffer(64);
            let pinBuffer        = UTF8toBuffer(pincode);

            encryptionBuffer.set(pinBuffer);

            let newPinEnc     = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(sharedSecret, encryptionBuffer);
            let newPinEncHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(sharedSecret, newPinEnc);
            let pinAuth       = newPinEncHMAC.slice(0, 16);

            let platPKXCoeff = platformPublicKey.slice(1,33);
            let platPKYCoeff = platformPublicKey.slice(33);

            let keyAgreement = {
                 '1': 2,
                '-1': 1,
                '3': -25,
                '-2': platPKXCoeff,
                '-3': platPKYCoeff
            }

            let commandBuffer = generateClientPin_SetPIN({
                pinAuth, newPinEnc, keyAgreement
            })

            return sendValidCTAP_CBOR(commandBuffer, {'dontResetCard': true})
        })
}

/**
 * Sends HMAC secret GetAssertion request to the authenticato with given salts
 * @param        {String} rpId   - Relying party identifier
 * @param  {BufferSource} credId - Credential Identifier
 * @param  {BufferSource} salt1  - Salt 1
 * @param  {BufferSource} salt2  - Optional Salt 2
 * @return {Object<string, BufferSource>} - Response dictionary with salt1Hmac and salt2Hmac
 */
let sendHmacSecretGetAssertion = (rpId, credId, salt1, salt2) => {
    if(!rpId || !credId || !salt1)
        throw new Error('For HMACExtension request credId and salt1 are mandatory params!');

    salt2 = salt2 || new Uint8Array();

    return establishKeyAgreement()                
        .then((ka) => {
            let getAssertionStruct = generateGoodCTAP2GetAssertion();
            let allowList          = [
                { 'type': 'public-key', 'id': credId }
            ]

            let salt = mergeArrayBuffers(salt1, salt2)

            let saltEnc       = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(ka.sharedSecret, salt);
            let newPinEncHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(ka.sharedSecret, saltEnc);
            let saltAuth      = newPinEncHMAC.slice(0, 16);

            let extensions = {
                'hmac-secret': {
                    0x01: ka.keyAgreement,
                    0x02: saltEnc,
                    0x03: saltAuth
                }
            }

            let commandBuffer  = generateGetAssertionReqCBOR(rpId, getAssertionStruct.clientDataHash, allowList, extensions)

            return sendValidCTAP_CBOR(commandBuffer)
                .then((ctap2Response) => {
                    assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);

                    let authDataBuffer = ctap2Response.cborResponseStruct[GetAssertionRespKeys.authData];
                    let authDataStruct = parseAuthData(authDataBuffer);

                    assert.isDefined(authDataStruct.extensionsData, 'Authenticator did not return any extensions data, despite claiming it\'s support of the "hmac-secret" extension!')

                    let extensionsStruct = vanillaCBOR.decode(authDataStruct.extensionsData)[0];
                    assert.isDefined(extensionsStruct['hmac-secret'], 'Extensions data does not contain any response for "hmac-secret" extension, despite claiming of it\'s support!')

                    let saltsHmac = window.navigator.fido.fido2.crypto.decryptAES256CBCIV0(ka.sharedSecret, extensionsStruct['hmac-secret'])

                    let salt1Hmac = saltsHmac.slice(0, 32);
                    let salt2Hmac = saltsHmac.slice(32);

                    console.log(saltsHmac)
                    if(salt2.length && salt2Hmac.length != 32)
                        throw new Error('Authenticator did not return 32 bytes HMAC of salt2!');

                    return { salt1Hmac, salt2Hmac }
                })
        })
}

/**
 * Generates pinAuthn token
 * @param  {String} pincode
 * @return {Promise<Buffer>} - decrypted pinAuth token
 */
var getPINToken = (pincode) => {
    let sharedSecret = undefined;
    return establishKeyAgreement()
        .then((response) => {
            sharedSecret              = response.sharedSecret;
            let pinCodeBuffer         = UTF8toBuffer(pincode);
            let pinCodeHashBuffer     = window.navigator.fido.fido2.crypto.hash('sha256', pinCodeBuffer);
            let pinCodeHashBufferLEFT = pinCodeHashBuffer.slice(0, 16);

            let pinHashEnc   = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(sharedSecret, pinCodeHashBufferLEFT);
            let keyAgreement = response.keyAgreement;

            let commandBuffer = generateClientPin_GetPINToken({pinHashEnc, keyAgreement})

            return sendValidCTAP_CBOR(commandBuffer, {'dontResetCard': true})
        })
        .then((response) => {
            let cborResponse       = response.cborResponse;
            let cborResponseStruct = response.cborResponseStruct;

            let pinTokenEnc = cborResponseStruct[ClientPinRespKeys.pinToken];
            let pinToken    = window.navigator.fido.fido2.crypto.decryptAES256CBCIV0(sharedSecret, pinTokenEnc);

            return pinToken
        })
}

/**
 * Generates pinAuthn un-encrypted(raw) token
 * @param  {String} pincode
 * @return {Promise<Buffer>} - decrypted pinAuth token
 */
var getPINTokenRaw = (pincode) => {
    let sharedSecret = undefined;
    return establishKeyAgreement()
        .then((response) => {
            sharedSecret              = response.sharedSecret;
            let pinCodeBuffer         = UTF8toBuffer(pincode);
            let pinCodeHashBuffer     = window.navigator.fido.fido2.crypto.hash('sha256', pinCodeBuffer);
            let pinCodeHashBufferLEFT = pinCodeHashBuffer.slice(0, 16);

            let pinHashEnc   = window.navigator.fido.fido2.crypto.encryptAES256CBCIV0(sharedSecret, pinCodeHashBufferLEFT);
            let keyAgreement = response.keyAgreement;

            let commandBuffer = generateClientPin_GetPINToken({pinHashEnc, keyAgreement})

            return sendCTAP_CBOR(commandBuffer, {'dontResetCard': true})
        })
}

var getRetries = () => {
    return sendValidCTAP_CBOR(generateClientPin_GetRetries(), {'dontResetCard': true})
        .then((ctap2Response) => {
            let cborResponse = ctap2Response.cborResponse;

            return cborResponse[ClientPinRespKeys.retries];  
        })
}

/**
 * Generates getKeyAgreement command
 * @return {Buffer} - getRetries command buffer
 */
var generateClientPin_GetKeyAgreement = () => {
    return generateClientPin({
        'pinProtocol': 0x01, 
        'subCommand': ClientPinSubCommands.getKeyAgreement
    })
}

/**
 * Generates getRetries command
 * @return {Buffer} - clientPinToken command buffer
 */
var generateClientPin_GetRetries = () => {
    return generateClientPin({
        'pinProtocol': 0x01,
        'subCommand': ClientPinSubCommands.getRetries
    })
}

/**
 * Generates setPIN command
 * @return {Buffer} - clientPinToken command buffer
 */
var generateClientPin_SetPIN = (requestObject) => {
    return generateClientPin({
        'pinProtocol': 0x01,
        'subCommand': ClientPinSubCommands.setPIN,
        'pinAuth': requestObject.pinAuth,
        'newPinEnc': requestObject.newPinEnc,
        'pinHashEnc': requestObject.pinHashEnc,
        'keyAgreement': requestObject.keyAgreement
    })
}

/**
 * Generates changePIN command
 * @return {Buffer} - clientPinToken command buffer
 */
var generateClientPin_ChangePIN = (requestObject) => {
    return generateClientPin({
        'pinProtocol': 0x01,
        'subCommand': ClientPinSubCommands.changePIN,
        'pinHashEnc': requestObject.pinHashEnc,
        'newPinEnc': requestObject.newPinEnc,
        'pinAuth': requestObject.pinAuth,
        'keyAgreement': requestObject.keyAgreement
    })
}

/**
 * Returns pin token
 * @return {Buffer} - clientPinToken command buffer
 */
var generateClientPin_GetPINToken = (requestObject) => {
    return generateClientPin({
        'pinProtocol': 0x01,
        'subCommand': ClientPinSubCommands.getPINToken,
        'pinHashEnc': requestObject.pinHashEnc,
        'keyAgreement': requestObject.keyAgreement
    })
}

/**
 * Send CBOR reset command
 * @return {Promise}
 */
var sendReset = () => {
    if(getDeviceInfo().transport === 'HID')
        alert('If your device requires power reset before sending reset, please unplug you device and plug it back in, otherwise please press enter.');

    // return new Promise((resolve, reject) => {
    //     sendCTAP_CBOR(generateResetRequest())
    //         .then(() => resolve())
    //         .catch(() => resolve())

    // })
    
    return sendValidCTAP_CBOR(generateResetRequest())
}


/**
 * Takes requestObject, which is a map of clientPing request structure, and returns cbor command buffer
 * @param  {Object} requestObject - MAP containing keys pinProtocol, subCommand, keyAgreement, pinAuth, newPinEnc, pinHashEnc
 * @return {Buffer}
 */
var generateClientPin = (requestObject) => {
    let struct = {
        0x01: requestObject.pinProtocol,
        0x02: requestObject.subCommand,
        0x03: requestObject.keyAgreement,
        0x04: requestObject.pinAuth,
        0x05: requestObject.newPinEnc,
        0x06: requestObject.pinHashEnc
    }

    let structBuff = window.navigator.fido.fido2.cbor.JSONToCBORArrayBuffer(struct);
    let finalBuff  = new Uint8Array(mergeArrayBuffers(new Uint8Array([CTAP2COMMANDS.authenticatorClientPIN]), structBuff));

    return finalBuff
}

/**
 * Takes makeCreditential arguments, and returns cbor buffer
 * @param  {Uint8Array} clientDataHash
 * @param  {Object} rp
 * @param  {Object} user
 * @param  {Object} pubKeyCredParams
 * @param  {Array} excludeList
 * @param  {Object} extensions
 * @param  {Object} options
 * @param  {Object} pinAuth
 * @param  {Object} pinProtocol
 * @return {Uint8Array}
 */
var generateMakeCreditentialsReqCBOR = (clientDataHash, rp, user, pubKeyCredParams, excludeList, extensions, options, pinAuth, pinProtocol) => {
    let struct = {
        0x01: clientDataHash,
        0x02: rp,
        0x03: user,
        0x04: pubKeyCredParams,
        0x05: excludeList,
        0x06: extensions,
        0x07: options,
        0x08: pinAuth,
        0x09: pinProtocol
    }

    let structBuff = window.navigator.fido.fido2.cbor.JSONToCBORArrayBuffer(struct);
    let finalBuff = new Uint8Array(mergeArrayBuffers(new Uint8Array([CTAP2COMMANDS.authenticatorMakeCredential]), structBuff));

    return finalBuff
}

let generateGoodCTAP2MakeCreditentials = () => {
    let rpId   = generateRandomDomain();
    let origin = 'https://' + generateRandomWord() + '.' + rpId;
    let clientData     = {
        'challenge': base64url.encode(generateRandomBuffer(32)),
        'origin'   : origin,
        'type'     : 'webauthn.create'
    }
    let clientDataHash = navigator.fido.fido2.crypto.hash('sha-256', JSON.stringify(clientData));

    let randomUserDomain = generateRandomDomain();
    let randomUserName   = generateRandomName();

    let user = {
        id: generateRandomBuffer(32),
        icon: 'https://pics.acme.com/00/p/aBjjjpqPb.png',
        name: generateEmailFromNameAndDomain(randomUserName, randomUserDomain),
        displayName: randomUserName
    }

    let rp = {
        name: 'The Example Corporation with fake domain!',
        id: rpId
    }

    let pubKeyCredParams = getMetadataPubKeyParams();

    return {clientDataHash, user, rp, pubKeyCredParams, clientData, rpId, origin}
}

var generateGoodCTAP2GetAssertion = (origin) => {
    let clientData     = {
        'challenge': base64url.encode(generateRandomBuffer(32)),
        'origin'   : origin,
        'type'     : 'webauthn.get'
    }
    let clientDataHash = navigator.fido.fido2.crypto.hash('sha-256', JSON.stringify(clientData));

    return {clientDataHash, clientData}
}

/**
 * Takes getAssertions arguments, and returns cbor buffer
 * @param  {String} rpId
 * @param  {Uint8Array} clientDataHash
 * @param  {Array} allowList
 * @param  {Object} extensions
 * @param  {Object} options
 * @param  {String} pinAuth
 * @param  {Object} pinProtocol
 * @return {Uint8Array}
 */
var generateGetAssertionReqCBOR = (rpId, clientDataHash, allowList, extensions, options, pinAuth, pinProtocol) => {
    let struct = {
        0x01: rpId,
        0x02: clientDataHash,
        0x03: allowList,
        0x04: extensions,
        0x05: options,
        0x06: pinAuth,
        0x07: pinProtocol
    }

    let structBuff = window.navigator.fido.fido2.cbor.JSONToCBORArrayBuffer(struct);
    let finalBuff = new Uint8Array(mergeArrayBuffers(new Uint8Array([CTAP2COMMANDS.authenticatorGetAssertion]), structBuff));

    return finalBuff
}

/**
 * Retuns a valid authenticatorReset request
 * @return {Uint8Array} Good Reset request buffer
 */
var generateResetRequest = () => {
    return new Uint8Array([0x07])
}

/**
 * Retuns a valid authenticatorGetInfo request
 * @return {Uint8Array} Good GetInfo request buffer
 */
var generateGetInfoRequest = () => {
    return new Uint8Array([0x04])
}

/**
 * Retuns a valid authenticatorGetNextRequest request
 * @return {Uint8Array} Good GetNextRequest request buffer
 */
var generateGetNextRequest = () => {
    return new Uint8Array([0x08])
}

/**
 * Tries to parse CBOR buffer, and if error occurs returns more frendly error 
 * @param  {Buffer} buffer - CBOR buffer
 * @return {Object}        - JS struct
 */
var tryDecodeCBORtoJSON = (buffer) => {
    try {
        return window.navigator.fido.fido2.cbor.CBORBufferToJSON(buffer);
    } catch(e) {
        throw new Error(`Error while decoding CBOR buffer. Parser returned error: ${e}. Try testing your CBOR at http://cbor.me/`)
    }
}

/**
 * Tries to parse CBOR buffer, and if error occurs returns more frendly error 
 * @param  {Buffer} buffer - CBOR buffer
 * @return {Object}        - CBOR struct
 */
var tryDecodeCBORtoCBORSTRUCT = (buffer) => {
    try {
        return window.navigator.fido.fido2.cbor.CBORBufferToSTRUCT(buffer);
    } catch(e) {
        throw new Error(`Error while decoding CBOR buffer. Parser returned error: ${e}. Try testing your CBOR at http://cbor.me/`)
    }
}

/**
 * Takes response buffer, and parses to easy to work structure.
 * @param  {Buffer} buffer
 * @return {Object}
 * Response.statusCode -> CTAP2 status code
 * Response.cborResponse -> CTAP2 CBOR decoded JSON response structure
 * Response.cborResponseStruct -> CTAP2 CBOR decoded Object response structure
 * Response.cborBuffer -> CTAP2 CBOR buffer
 */
var parseCTAP2Response = (buffer) => {
    buffer = convertToUint8Array(buffer);
    let statusCode = buffer[0];

    let cborResponse;
    let cborResponseStruct;
    let cborBuffer;
    if(statusCode === CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS) {
        cborBuffer   = buffer.slice(1);
        cborResponse = window.navigator.fido.fido2.cbor.CBORBufferToJSON(cborBuffer)[0];
        cborResponseStruct = window.navigator.fido.fido2.cbor.CBORBufferToSTRUCT(cborBuffer)[0];
    }

    return {
        statusCode, cborResponse, cborResponseStruct, cborBuffer
    }
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
var parseAuthData = (buffer) => {
    buffer = convertToUint8Array(buffer);

    if(buffer.byteLength < 37)
        throw new Error('authData can NOT be shorter than 37 bytes!');

    let rpIdHash      = buffer.slice(0, 32);              buffer = buffer.slice(32);

    /* Flags */
    let flagsBuf      = buffer.slice(0, 1);               buffer = buffer.slice(1);
    let flagsInt      = flagsBuf[0];
    let up            = !!(flagsInt & 0x01); // Test of User Presence
    let uv            = !!(flagsInt & 0x04); // User Verification
    let at            = !!(flagsInt & 0x40); // Attested credential data included (AT).
    let ed            = !!(flagsInt & 0x80); // Extension data
    let flags = {up, uv, at, ed, flagsInt};

    let counterBuf    = buffer.slice(0, 4);               buffer = buffer.slice(4);
    let counter       = readBE32(counterBuf);

    /* Attested credential data */
    let hexaaguid     = undefined;
    let aaguid        = undefined;
    let credId        = undefined;
    let COSEPublicKey = undefined;
    if(at) { // If authenticatorData includes Attested credential data
        if(buffer.byteLength < 16 + 2 + 16 + 77)
            throw new Error('AT flag is set, but leftover buffer is less then 111(16 + 2 + 16 + 77) bytes long! Maybe you\'ve accidentally set AT flag for getAssertions?');

        hexaaguid     = hex.encode(buffer.slice(0, 16));  buffer = buffer.slice(16);
        aaguid        = `${hexaaguid.slice(0, 8)}-${hexaaguid.slice(8, 12)}-${hexaaguid.slice(12, 16)}-${hexaaguid.slice(16, 20)}-${hexaaguid.slice(20)}`;

        let credIdLenBuf = buffer.slice(0, 2);               buffer = buffer.slice(2);
        let credIdLen    = readBE16(credIdLenBuf);
        credId           = buffer.slice(0, credIdLen);       buffer = buffer.slice(credIdLen);

        let pubKeyLength = vanillaCBOR.decodeOnlyFirst(buffer).byteLength;
        COSEPublicKey = buffer.slice(0, pubKeyLength);       buffer = buffer.slice(pubKeyLength);
    }

    let extensionsData = undefined;
    if(ed) {
        let extensionsDataLength = vanillaCBOR.decodeOnlyFirst(buffer).byteLength;

        extensionsData = buffer.slice(0, extensionsDataLength); buffer = buffer.slice(extensionsDataLength);
    }

    if(buffer.byteLength)
        throw new Error('Failed to decode authData! Leftover bytes been detected!');

    return {rpIdHash, counter, flags, counterBuf, aaguid, credId, COSEPublicKey, extensionsData}
}

/**
 * Takes COSE public key object and returns FIDO Registry equivalent algorithm
 * @param  {Object} COSEPublicKeyStruct - COSE Key Object
 * @return {String}                     - FIDO Registry Identifier
 */
var getFIDOAlgorithm = (COSEPublicKeyStruct) => {
    let kty = COSEPublicKeyStruct[COSE_KEYS.kty]
    let alg = COSEPublicKeyStruct[COSE_KEYS.alg]
    let crvStr = '';
    if(kty && kty !== COSE_KTY.RSA) {
        let crv = COSEPublicKeyStruct[COSE_KEYS.crv];
        crvStr  = ',crv:' + crv;
    }

    let identifier = `alg:${alg}${crvStr}`;

    let fidoAlgname = COSE_TO_FIDO_ALG[identifier];

    if(!fidoAlgname)
        throw new Error('Unknown algorithm identifiers! Can not find matching FIDO algorithm for ' + identifier);

    return fidoAlgname
}

/**
 * Returns an array of COSE algorithms based of the metadata statement
 * @return {Array<Number>}
 */
var getMetadataPubKeyParams = () => {
    let metadataStatement = getMetadataStatement();
    let fidoAlgorithms    = [metadataStatement.authenticationAlgorithm];

    if(metadataStatement.authenticationAlgorithms)
        fidoAlgorithms = fidoAlgorithms.concat(metadataStatement.authenticationAlgorithms);

    let pubKeyCredParams = fidoAlgorithms.map((fidoAlg) => {
        let fidoAuthAlg  = AUTHENTICATION_ALGORITHMS[metadataStatement.authenticationAlgorithm];
        let coseParams   = FIDO_ALG_TO_COSE[fidoAuthAlg];

        if(!coseParams)
            throw new Error(`The FIDO algorithm ${fidoAuthAlg}(${hexifyInt(metadataStatement.authenticationAlgorithm)}) is not supported by FIDO2. Maybe try changing from DER to RAW?`);

        return {
            type: 'public-key',
            alg: coseParams.alg
        }
    })

    return pubKeyCredParams
}



/**
 * Takes COSE public key object
 * @param  {Object} COSEPublicKeyStruct - COSE Key Object
 * @return {String}                     - FIDO Registry Identifier
 */
var getFIDOAlgorithmParams = (COSEPublicKeyStruct) => {
    let fidoAlgname = getFIDOAlgorithm(COSEPublicKeyStruct)

    if(!fidoAlgname)
        throw new Error('Unknown algorithm identifiers! Can not find matching FIDO algorithm for ' + identifier);

    let response = Object.assign({}, FIDO_ALG_TO_COSE[fidoAlgname])
    response.fidoAlgname   = fidoAlgname;  

    return response
}

/**
 * Takes PKCS ECDSA public key buffer, and returns COSE encoded public key
 * @param  {Uint8Array} asn1PublicKeyBuffer
 * @return {Uint8Array}
 */
let PKCSECDSAtoCOSE = (asn1PublicKeyBuffer) => {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       +------+-------+-------+---------+----------------------------------+
    */
   
    if(asn1PublicKeyBuffer.byteLength !== 65)
        throw new Error('asn1PublicKeyBuffer is NOT 65 bytes long!');

    asn1PublicKeyBuffer = asn1PublicKeyBuffer.slice(1);

    let xCoefficient = asn1PublicKeyBuffer.slice(0,32);
    let yCoefficient = asn1PublicKeyBuffer.slice(32);

    let COSESTRUCT = {
         '1': 2,  // EC2 key
         '3': -7, // ES256
        '-1': 1,  // P-256 
        '-2': xCoefficient,
        '-3': yCoefficient
    }

    return window.navigator.fido.fido2.cbor.JSONToCBORArrayBuffer(COSESTRUCT)
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Object} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
var COSEECDHAtoPKCS = (coseStruct) => {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    let tag = new Uint8Array([0x04])
    let x   = hex.decode(coseStruct[-2]);
    let y   = hex.decode(coseStruct[-3]);

    return new Uint8Array(mergeArrayBuffers(tag, x, y))
}

/**
 * Takes credentialCounter and retrieves all assertion with generateGetNextRequest
 * @param  {Number}              credentialCounter - number of credentials
 * @return {Array<CBORResponse>}
 */
var getRemainingGetNextCredentials = (credentialCounter) => {
    let assertions = [];

    let sendGetNext = () =>  {
        return sendValidCTAP_CBOR(generateGetNextRequest(), undefined, true)
        .then((response) => {
            credentialCounter--;

            assertions.push(response);

            if(credentialCounter > 0)
                return sendGetNext()
            else
                return assertions
        })
    }

    return sendGetNext()
}

/**
 * Takes TPMT_PUBLIC buffer and returns parsed structure
 * @param  {Buffer} pubAreaBuffer
 * @return {Object}
 */
var parseTPMT_PUBLIC = (pubAreaBuffer) => {
    let typeBuffer = pubAreaBuffer.slice(0, 2);
    let type       = TPM_ALG_ID[readBE16(typeBuffer)];
    pubAreaBuffer  = pubAreaBuffer.slice(2);

    let nameAlgBuffer = pubAreaBuffer.slice(0, 2)
    let nameAlg       = TPM_ALG_ID[readBE16(nameAlgBuffer)];
    pubAreaBuffer     = pubAreaBuffer.slice(2);

    let objectAttributesBuffer = pubAreaBuffer.slice(0,4);
    let objectAttributesInt    = readBE32(objectAttributesBuffer);
    let objectAttributes = {
        fixedTPM:             !!(objectAttributesInt & 1),
        stClear:              !!(objectAttributesInt & 2),
        fixedParent:          !!(objectAttributesInt & 8),
        sensitiveDataOrigin:  !!(objectAttributesInt & 16),
        userWithAuth:         !!(objectAttributesInt & 32),
        adminWithPolicy:      !!(objectAttributesInt & 64),
        noDA:                 !!(objectAttributesInt & 512),
        encryptedDuplication: !!(objectAttributesInt & 1024),
        restricted:           !!(objectAttributesInt & 32768),
        decrypt:              !!(objectAttributesInt & 65536),
        signORencrypt:        !!(objectAttributesInt & 131072)
    }
    pubAreaBuffer = pubAreaBuffer.slice(4);

    let authPolicyLength = readBE16(pubAreaBuffer.slice(0, 2));
    pubAreaBuffer  = pubAreaBuffer.slice(2);
    let authPolicy = pubAreaBuffer.slice(0, authPolicyLength);
    pubAreaBuffer  = pubAreaBuffer.slice(authPolicyLength);

    let parameters = undefined;
    if(type === 'TPM_ALG_RSA') {
        parameters = {
            symmetric: TPM_ALG_ID[readBE16(pubAreaBuffer.slice(0, 2))],
            scheme:    TPM_ALG_ID[readBE16(pubAreaBuffer.slice(2, 4))],
            keyBits:   readBE16(pubAreaBuffer.slice(4, 6)),
            exponent:  readBE32(pubAreaBuffer.slice(6, 10))
        }
        pubAreaBuffer  = pubAreaBuffer.slice(10);
    } else if(type === 'TPM_ALG_ECC') {
        parameters = {
            symmetric: TPM_ALG_ID[readBE16(pubAreaBuffer.slice(0, 2))],
            scheme:    TPM_ALG_ID[readBE16(pubAreaBuffer.slice(2, 4))],
            curveID:   TPM_ECC_CURVE[readBE16(pubAreaBuffer.slice(4, 6))],
            kdf:       TPM_ALG_ID[readBE16(pubAreaBuffer.slice(6, 8))]
        }
        pubAreaBuffer  = pubAreaBuffer.slice(8);
    } else 
        throw new Error(type + ' is an unsupported type!');

    let uniqueLength = readBE16(pubAreaBuffer.slice(0, 2));
    pubAreaBuffer  = pubAreaBuffer.slice(2);
    let unique = pubAreaBuffer.slice(0, uniqueLength);
    pubAreaBuffer  = pubAreaBuffer.slice(uniqueLength);

    if(pubAreaBuffer.length)
        throw new Error('TPMT_PUBLIC contains leftover bytes!');

    return {type, nameAlg, objectAttributes, authPolicy, parameters, unique}
}

/**
 * Takes TPMS_ATTEST buffer and returns parsed structure
 * @param  {Buffer} certInfoBuffer
 * @return {Object}
 */
var parseTPMS_ATTEST = (certInfoBuffer) => {
    let magicBuffer = certInfoBuffer.slice(0, 4);
    let magic = readBE32(magicBuffer);
    certInfoBuffer = certInfoBuffer.slice(4);

    let typeBuffer = certInfoBuffer.slice(0, 2);
    let type = TPM_ST[readBE16(typeBuffer)];
    certInfoBuffer = certInfoBuffer.slice(2);

    let qualifiedSignerLength = readBE16(certInfoBuffer.slice(0, 2));
    certInfoBuffer  = certInfoBuffer.slice(2);
    let qualifiedSigner = certInfoBuffer.slice(0, qualifiedSignerLength);
    certInfoBuffer  = certInfoBuffer.slice(qualifiedSignerLength);

    let extraDataLength = readBE16(certInfoBuffer.slice(0, 2));
    certInfoBuffer  = certInfoBuffer.slice(2);
    let extraData  = certInfoBuffer.slice(0, extraDataLength);
    certInfoBuffer  = certInfoBuffer.slice(extraDataLength);

    let clockInfo = {
        clock: certInfoBuffer.slice(0, 8),
        resetCount: readBE32(certInfoBuffer.slice(8, 12)),
        restartCount: readBE32(certInfoBuffer.slice(12, 16)),
        safe: !!(certInfoBuffer[16])
    }
    certInfoBuffer  = certInfoBuffer.slice(17);

    let firmwareVersion = certInfoBuffer.slice(0, 8);
    certInfoBuffer      = certInfoBuffer.slice(8);

    let attestedNameBufferLength = readBE16(certInfoBuffer.slice(0, 2))
    let attestedNameBuffer = certInfoBuffer.slice(2, attestedNameBufferLength + 2);
    certInfoBuffer = certInfoBuffer.slice(2 + attestedNameBufferLength)

    let attestedQualifiedNameBufferLength = readBE16(certInfoBuffer.slice(0, 2))
    let attestedQualifiedNameBuffer = certInfoBuffer.slice(2, attestedQualifiedNameBufferLength + 2);
    certInfoBuffer = certInfoBuffer.slice(2 + attestedQualifiedNameBufferLength)

    let attested = {
        name: attestedNameBuffer,
        qualifiedName: attestedQualifiedNameBuffer
    }

    if(certInfoBuffer.length)
        throw new Error('TPMS_ATTEST contains leftover bytes!');

    return { magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion, attested }
}

var getMakeCredentialResponseForAllAlgorithms = (rpId) => {
    let pubKeyCredParamsJobs = getMetadataPubKeyParams();
    let responses        = [];
    
    let getAlgorithmAssertion = () => {
        if(!pubKeyCredParamsJobs.length)
            return Promise.resolve(responses);

        let pubKeyCredParams = [pubKeyCredParamsJobs.pop()];
        let makeCredStruct   = generateGoodCTAP2MakeCreditentials();
        makeCredStruct.rp.id = rpId;
        let commandBuffer    = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, pubKeyCredParams)

        return sendCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);

                let cborResponse       = ctap2Response.cborResponse;
                let cborResponseStruct = ctap2Response.cborResponseStruct;
                let clientDataHash     = makeCredStruct.clientDataHash;

                responses.push({cborResponse, cborResponseStruct, clientDataHash})

                return getAlgorithmAssertion()
            })
    }


    return getAlgorithmAssertion()
}

/**
 * Send CTAPHID_CBOR command
 * @param  {Buffer} requestBuffer - request buffer
 * @param  {Object} options - options for call
 * @return {Promise<CTAP2Response>}
 */
var sendCTAP_CBOR = (requestBuffer, options) => {
    let deviceInfo = getDeviceInfo();

    let transportPromise = undefined;
    if(deviceInfo.transport === 'HID')
        transportPromise = sendCTAPHID_CBORCommand(requestBuffer);
    else if (deviceInfo.transport === 'NFC')
        transportPromise = sendShortCTAPNFC_CBORCommand(requestBuffer, options);
    else if(deviceInfo.transport === 'BLE')
        transportPromise = sendCTAPBLE_CBORCommand(requestBuffer);
    else
        throw new Error(`"${deviceInfo.transport}" is an unsupported transport!`);

    return transportPromise
        .then((result) => {
            let ctap2Response = parseCTAP2Response(result)

            return ctap2Response
        })
}

var sendValidCTAP_CBOR = (requestBuffer, options) => {
    return sendCTAP_CBOR(requestBuffer, options)
        .then((ctap2Response) => {
            if(ctap2Response.statusCode !== CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)
                throw new Error(`Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${ctap2Response.statusCode})`);

            return ctap2Response
        })
}
