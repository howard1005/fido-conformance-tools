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
 * This is the source code for pre-start rebuild.
 */

const spawn = require('cross-spawn');
const os    = require('os');

let rebuildlist = [
    'node-hid',
    'pcsclite',
    'xpc-connection',
    'buffertools'
]

if(os.platform() === 'win32')
    rebuildlist.push('noble-winrt');

spawn.sync('electron-rebuild', ['--force', '--only=' + rebuildlist.join(',')], { stdio: 'inherit' });