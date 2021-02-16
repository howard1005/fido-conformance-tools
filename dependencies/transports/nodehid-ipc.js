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

const path          = require('path');
const { ipcMain }   = require('electron')
const { fork }      = require('child_process');
const isPrivileged  = require('../isPrivileged')();
const os            = require('os');

var forked = undefined;
let connectProcess = () => {
    console.log('Connecting process...')
    forked = fork(path.join(__dirname, 'nodehid.fork.js'));
    forked.on('message', (response) => {
        if(response.cmd === 'logger') 
            return logger(response)

        if(!requestCallbackDB[response.cmd])
            throw new Error('Unknown response!');

        requestCallbackDB[response.cmd](response);
        requestCallbackDB[response.cmd] = undefined;
    })
    forked.on('error', (error) => {
        console.log('Error', error)
    })


    forked.on('close', (code) => {
        if (code !== 0) {
            console.log(`grep process exited with code ${code}`);
            connectProcess();
        }
    })

    forked.on('disconnect', (error) => {
        console.log('Process disconnected!')
    })
}
connectProcess();


let requestCallbackDB = {}
let processRequestManager = (request, callback) => {
    if(requestCallbackDB[request.cmd])
        console.log('Rewriting callback for: ' + request.cmd);

    requestCallbackDB[request.cmd] = callback;

    forked.send(request)
}

let callbackHook = undefined;
ipcMain.on('logger-async-init-request', (event, arg) => {
    callbackHook = (msg) => {
        event.sender.send('logger-async-reply', msg);
    }
})


/**
 * Logs what ever HID API returns
 */
let logger = (response) => {
    if(response.status === 'fail') {
        callbackHook(response.error);
        console.error(response.error);
    } else {
        callbackHook(response.data);
        console.log(response.data);
    }
}

/* ----- IPC ----- */
    let sendSuccess = (id, event, data) => {
        event.sender.send(id, {
            'status': 'ok',
            'data': data
        })
    }

    let sendFail = (id, event, error) => {
        event.sender.send(id, {
            'status': 'error',
            'error': error
        })
    }

    // let eventNumber = 0;
    ipcMain.on('send-hid-buffers-async-message', (event, arg) => {
        arg.cmd = 'sendHIDBuffers';
        arg.buffersArray = arg.buffersArray.map((buff) => Array.from(buff));

        processRequestManager(arg, (response) => {
            if(response.status === 'ok')
                sendSuccess('send-hid-buffers-async-reply', event, response.data)
            else
                sendFail('send-hid-buffers-async-reply', event, response.error)
        })
    })

    /**
     * Closes device defined by given deviceInfo
     * @param  {DeviceInfo} deviceInfo - Node HID device info object
     */
    ipcMain.on('close-device-sync', (event, deviceInfo) => {
        event.returnValue = {
            'status': 'ok'
        }
    })

    /**
     * Writes synchronously array of buffers.
     * @param  {DeviceInfo} deviceInfo     - Node HID device info object
     * @param  {ArrayBuffer[]} buffersArray - An array of Buffers to send  
     */
    ipcMain.on('send-hid-buffers-sync', (event, arg) => {
        arg.cmd = 'sendHIDBuffersSync';
        processRequestManager(arg, (response) => {
            if(response.status === 'ok')
                event.returnValue = {
                    'status': 'ok'
                }
            else
                event.returnValue = {
                    'status': 'error',
                    'error': response.error
                }            
        })
    })

    /**
     * Sends CTAP HID CANCEL
     * @return {DeviceInfo[]}
     */
    ipcMain.on('send-hid-cancel-sync', (event, arg) => {
        arg.cmd = 'sendCancel';
        processRequestManager(arg, (response) => {
            event.returnValue = response;
        })
    })

    /**
     * Synchronously reads device response
     * @param  {DeviceInfo} deviceInfo     - Node HID device info object
     * @return {ArrayBuffer}
     */
    ipcMain.on('read-hid-response-sync', (event, arg) => {
        arg.cmd = 'readHIDBuffersSync';
        processRequestManager(arg, (response) => {
            if(response.status === 'ok')
                event.returnValue = {
                    'status': 'ok',
                    'data': response.data
                }
            else
                event.returnValue = {
                    'status': 'error',
                    'error': response.error
                }
        })
    })

    /**
     * Returns a list of available FIDO devices
     * @return {DeviceInfo[]}
     */
    let fidoDevices = [];
    ipcMain.on('get-fido-devices-sync', (event) => {
        if(isPrivileged || os.platform() !== 'win32') {
            processRequestManager({'cmd': 'getFIDODevices'}, (response) => {
                event.returnValue = response.data;
            })
        } else {
            event.returnValue = [{
                path: 'error',
                transport: 'HID',
                product: 'To test FIDO2 authenticators on windows, you must be running tools as Administrator! Please close the tools, right click the Icon, and select "Run as Administrator"!'
            }]
        }
    })

    /**
     * Sets custom HID packet size
     * @return {DeviceInfo[]}
     */
    ipcMain.on('set-custom-packet-size-sync', (event, arg) => {
        processRequestManager({'cmd': 'setCustomPacketSize', 'customPacketSize': arg}, () => {
            event.returnValue = true;
        })
    })

    /**
     * Returns a list of all available HID devices
     * @return {DeviceInfo[]}
     */
    ipcMain.on('get-all-devices-sync', (event) => {
        processRequestManager({'cmd': 'getAllDevices'}, (response) => {
            event.returnValue = response.data;
        })
    })
/* ----- IPC END ----- */

