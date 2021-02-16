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

const hiddep    = require('./transports/hiddep');
const nfcdep    = require('./transports/nfcdep');
const bledep    = require('./transports/bledep');
const cryptodep = require('./cryptodep');
const cbordep   = require('./cbordep');
const {ipcRenderer} = require('electron');

let methods = {
    'crypto': cryptodep,
    'hid'   : hiddep,
    'nfc'   : nfcdep,
    'ble'   : bledep,
    'cbor'  : cbordep
}

ipcRenderer.on('logger-async-reply', (event, arg) => {
    console.log(arg)
})
ipcRenderer.send('logger-async-init-request', 'ping')

module.exports = methods;
