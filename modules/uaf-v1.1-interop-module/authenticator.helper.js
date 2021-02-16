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

var authenticator = {
    canOpenUAFURL : () => {
        return new Promise((resolve, reject) => {
            window.window.navigator.fido.uafclient.canOpenUAFURL((result) => resolve(result))
        })
    },

    getClientList : () => {
        return new Promise((resolve, reject) => {
            window.window.navigator.fido.uafclient.getClientList((result) => resolve(result))
        })
    },

    discover : () => {
        return new Promise(function(resolve, reject) {
            if(!window.navigator.fido.uaf || !window.navigator.fido.uaf.discover) {
                window.window.navigator.fido.uafclient.discover(
                    (response) => {
                        resolve(response);
                    },

                    (error) => {
                        reject(error);
                    }
                )
            } else {
                window.navigator.fido.uaf.discover(
                    (response) => {
                        resolve(response);
                    },

                    (error) => {
                        reject(error);
                    }
                )
            }
        })
    },

    checkPolicy : (message) => {
         return new Promise(function(resolve, reject) {
            if(!window.navigator.fido.uaf || !window.navigator.fido.uaf.checkPolicy) {
                window.window.navigator.fido.uafclient.checkPolicy(
                    message,
                    
                    (error) => {
                        resolve(error);
                    }
                )
            } else {
                window.navigator.fido.uaf.checkPolicy(
                    message,
                    
                    (error) => {
                        resolve(error);
                    }
                )
            }
        })
    },

    processUAFOperation : (message) => {
        return new Promise(function(resolve, reject) {
            if(!window.navigator.fido.uaf || !window.navigator.fido.uaf.processUAFOperation) {
                window.window.navigator.fido.uafclient.processUAFOperation(
                    message,
                    
                    (response) => {
                        resolve(response);
                    }, 

                    (error) => {
                        reject(error);
                    }
                )
            } else {
                window.navigator.fido.uaf.processUAFOperation(
                    message,
                    
                    (response) => {
                        resolve(response);
                    }, 

                    (error) => {
                        reject(error);
                    }
                )
            }
        })
    },

    notifyUAFResult : (responseCode, uafResponse) => {
        if(!window.navigator.fido.uaf || !window.navigator.fido.uaf.notifyUAFResult) {
            window.window.navigator.fido.uafclient.notifyUAFResult(responseCode, uafResponse)
        } else {
            window.navigator.fido.uaf.notifyUAFResult(responseCode, uafResponse)
        }
    }
}