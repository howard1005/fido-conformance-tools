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
 * Main Electron start file
 */
const {app, protocol, BrowserWindow, session, ipcMain} = require('electron');
const contextMenu   = require('electron-context-menu');
const path          = require('path');
const url           = require('url');
const isDevEnv      = require('electron-is-dev');
const isPrivileged  = require('./dependencies/isPrivileged')();

/* ----- Transport level IPC activation ----- */
const hidipc   = require('./dependencies/transports/nodehid-ipc');
const nobleipc = require('./dependencies/transports/noble-ipc');

/* ----- Starting WebApp ----- */
const webhost  = require('./webapp')

console.log('ELECTRON VERSION: ' + process.versions.electron);
console.log('NODE VERSION: ' + process.versions.node);
console.log('IS ADMIN: ' + isPrivileged);

/* ----- IPC ----- */
    ipcMain.on('force-reload-page', () => {
        mainWindow.webContents.reloadIgnoringCache();
    })

    /**
     * Open inspector on 'open-inspector' event call from renderer
     */
    ipcMain.on('open-inspector', function (store) {
        console.log('Opening inspector');
        initializeDebugMode();
    });

        /**
     * Open inspector on 'open-inspector' event call from renderer
     */
    ipcMain.on('quit-app', function (store) {
        app.quit();
    });
/* ----- IPC ENDS ----- */

/* ----- startup stuff ----- */

    // make "file://" Privileged to be able to access user request files  
    protocol.registerSchemesAsPrivileged([{
        scheme: 'file',
        privileges: {
            standard:        true,
            secure:          true,
            supportFetchAPI: true
        }
    }])

    app.allowRendererProcessReuse = false;

    let initializeDebugMode = () => {
        contextMenu({
            prepend: (params, browserWindow) => [{
                label: 'Rainbow',
                // Only show it when right-clicking images 
                visible: params.mediaType === 'image'
            }]
        })

        mainWindow.webContents.openDevTools()
    }

    let mainWindow;
    function createWindow () {
        mainWindow = new BrowserWindow({
            width: 800,
            height: 600,
            webPreferences: {
                nodeIntegration: false,
                preload: path.join(__dirname, 'preload.js')
            }
        })

        mainWindow.loadURL(url.format({
            pathname: path.join(__dirname, 'app/index.html'),
            protocol: 'file:',
            slashes: true
        }))

        mainWindow.webContents.on('crashed', (event, killed) => {
            console.log(event)
            console.log(`Crashed? ${mainWindow.webContents.isCrashed()}`)
            console.log(`Killed? ${killed}`)
        })

        mainWindow.webContents.on('will-navigate', (event, killed) => {
            event.preventDefault()
        })

        mainWindow.on('closed', () => {
            mainWindow = null
        })

        if(isDevEnv)
            initializeDebugMode()
        else
            mainWindow.setMenu(null);
    }

    app.on('ready', createWindow)
    app.on('window-all-closed', () => {
        if(process.platform !== 'darwin')
            app.quit();
    })

    app.on('activate', () => {
        if(mainWindow === null)
            createWindow();
    })

    app.on('web-contents-created', (event, contents) => {
        if(contents.getType() == 'webview') {
            contents.on('will-navigate', (event, url) => {
                event.preventDefault()
            })
        }
    })

    app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
        if(url.startsWith('https://localhost')) {
            event.preventDefault()
            callback(true)
        } else {
            callback(false)
        }
    })
/* ----- Startup stuff ends ----- */
