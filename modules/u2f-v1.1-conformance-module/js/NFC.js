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
 * Sends CTAPNFC_INIT command and returns new CID
 * @return {ArrayBuffer} - New assigned CID
 */
let sendCTAPNFC_INITCommand = () => {
    let appletSelectionCommand = new Uint8Array([0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    return navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), [appletSelectionCommand], true)
        .then((response) => {
            if(hex.encode(response[0]) !== '5532465f5632' && hex.encode(response[0]) !== '4649444f5f325f30')
                throw new Error('Unable to select FIDO applet!');

            return
        })
}

/**
 * Send CTAP_CBOR command wrapped in Short APDU chain
 * @param  {Buffer} requestFrames - request Frames
 * @return {Promise<CTAP2Response>}
 */
let sendCTAPNFC_MSGCommand = (requestFrames, options) => {
    options = options || {};
    return window.navigator.fido.fido2.nfc.sendNFCAPDUBuffers(getDeviceInfo(), requestFrames, options.noInit, options.dontResetCard)
        .then((result) => {
            let base = new Uint8Array();

            for(let buff of result)
                base = mergeArrayBuffers(base, buff)

            return base
        })
        .catch((error) => {
            console.error(`Received NFC API error! Errorcode is ${error.statusCodeDef}(${hexifyInt(error.statusCode)}). The message is: ${error.errorMessage} `)

            return getBigEndianEcoding(new Uint8Array(new Uint16Array([error.statusCode]).buffer))
        })
}
