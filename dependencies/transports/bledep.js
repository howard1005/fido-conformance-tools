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

const {ipcRenderer} = require('electron');

module.exports = {
    'sendFIDOBuffers': (deviceInfo, buffers, protocol, bypassKeepAliveCheck) => {
        console.log(protocol, 'sendFIDOBuffers', deviceInfo, buffers)
        if(!deviceInfo || !buffers)
            throw new Error('Missing deviceInfo and/or buffersArray arguments!');

        let requestPayload = {deviceInfo, buffers, protocol, bypassKeepAliveCheck}
       
        return new Promise((resolve, reject) => {
            ipcRenderer.once('sendFIDOBuffers-async-response', (event, response) => {
                console.log(response)
                if(typeof tryInterval !== 'undefined')
                    clearInterval(tryInterval);

                if(response.status === 'ok') {
                    // Sometimes lower layers returns NODEJS buffer instead of generic Uint8Array, so we forcefully convert it to Uint8Array before passing further
                    if(response.data.DATA)
                        response.data.DATA = new Uint8Array(Array.from(response.data.DATA));

                    resolve(response.data)
                } else
                    reject(response.error)
            })

            let deviceConnected = ipcRenderer.sendSync('getState-sync', deviceInfo) === 'connected';

            if(deviceConnected) {
                ipcRenderer.send('sendFIDOBuffers-async-request', requestPayload)
            } else {
                setTimeout(() => {
                    alert('Waiting to connect authenticator...')
                }, 1)

                let tryInterval = setInterval(() => {
                    deviceConnected = ipcRenderer.sendSync('getState-sync', deviceInfo) === 'connected';
                    if(deviceConnected)
                        ipcRenderer.send('sendFIDOBuffers-async-request', requestPayload)

                }, 250)
            }

        })
    },

    'getFIDOCharacteristics': (deviceInfo) => {
        if(!deviceInfo)
            throw new Error('Missing deviceInfo argument!');

        let deviceConnected = ipcRenderer.sendSync('bleDeviceExist-sync', deviceInfo)
        if(!deviceConnected)
            throw new Error('Device ' + deviceInfo.uuid + ' is not connected!');

        return ipcRenderer.sendSync('getFIDOCharacteristics-sync', deviceInfo)
    },

    'getMaxWriteLength': (deviceInfo) => {
        if(!deviceInfo)
            throw new Error('Missing deviceInfo argument!');

        let deviceConnected = ipcRenderer.sendSync('bleDeviceExist-sync', deviceInfo)
        if(!deviceConnected)
            throw new Error('Device ' + deviceInfo.uuid + ' is not connected!');

        return ipcRenderer.sendSync('getMaxWriteLength-sync', deviceInfo)
    },

    'getServiceRevisionBitfield': (deviceInfo) => {
        if(!deviceInfo)
            throw new Error('Missing deviceInfo argument!');

        let deviceConnected = ipcRenderer.sendSync('bleDeviceExist-sync', deviceInfo)
        if(!deviceConnected)
            throw new Error('Device ' + deviceInfo.uuid + ' is not connected!');

        return ipcRenderer.sendSync('getServiceRevisionBitfield-sync', deviceInfo)
    },

    'getServiceRevision': (deviceInfo) => {
        if(!deviceInfo)
            throw new Error('Missing deviceInfo argument!');

        let deviceConnected = ipcRenderer.sendSync('bleDeviceExist-sync', deviceInfo)
        if(!deviceConnected)
            throw new Error('Device ' + deviceInfo.uuid + ' is not connected!');

        return ipcRenderer.sendSync('getServiceRevision-sync', deviceInfo)
    },

    'getPrimaryServiceUUID': (deviceInfo) => {
        if(!deviceInfo)
            throw new Error('Missing deviceInfo argument!');

        let deviceConnected = ipcRenderer.sendSync('bleDeviceExist-sync', deviceInfo)
        if(!deviceConnected)
            throw new Error('Device ' + deviceInfo.uuid + ' is not connected!');

        let primaryService = ipcRenderer.sendSync('getPrimaryService-sync', deviceInfo);

        if(!primaryService)
            throw new Error('Device does not have primary service set!');

        return primaryService.uuid
    },

    'getConnectedDevices': () => {
        return ipcRenderer.sendSync('getConnectedDevices-sync', '')
    },

    'getAllServices': (deviceInfo) => {
        if(!deviceInfo)
            throw new Error('Missing deviceInfo argument!');

        let deviceConnected = ipcRenderer.sendSync('bleDeviceExist-sync', deviceInfo)
        if(!deviceConnected)
            throw new Error('Device ' + deviceInfo.uuid + ' is not connected!');

        return ipcRenderer.sendSync('getAllServices-sync', deviceInfo)
    },

    'getState': (deviceInfo) => {
        if(!deviceInfo)
            throw new Error('Missing deviceInfo argument!');

        return ipcRenderer.sendSync('getState-sync', deviceInfo)
    },

    'resetMinRSSI': () => {
        return ipcRenderer.sendSync('resetRSSI-sync');
    },

    'setMinRSSI': (newValue) => {
        return ipcRenderer.sendSync('setRSSI-sync', newValue);
    },

    'getDeviceRSSI': (deviceInfo) => {
        if(!deviceInfo)
            throw new Error('Missing deviceInfo argument!');

        return ipcRenderer.sendSync('getRSSI-sync', deviceInfo)
    },

    'resetDevices': () => {
        return ipcRenderer.sendSync('resetDevices-sync')
    },

    'disable': () => {
        return ipcRenderer.sendSync('disableBLE-sync')
    },

    'enable': () => {
        return ipcRenderer.sendSync('enableBLE-sync')
    }
}
