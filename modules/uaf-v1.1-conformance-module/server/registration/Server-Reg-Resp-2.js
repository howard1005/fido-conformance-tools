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

describe(`

        Server-Reg-Resp-2

        Test server processing of the Registration Response Messages dictionary

    `, function() {

    this.timeout(5000);
    this.retries(3);

/* ---------- Negative Tests ---------- */
    describe(`F-1

        Get three registration requests, and for each respond with registration response with "header" set to "undefined", "null" and "empty" dictionary, correspondingly. Server must reject every response. 

    `, () => {
        it('header is undefined', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);

                    messages[0].header = undefined;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('header is null', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);

                    messages[0].header = null;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('header is empty Dictionary', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);

                    messages[0].header = {};

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-2

        Get registration request, and generate registration response with "header" set to type of NOT A Dictionary, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let messages = tryDecodeJSON(success.uafProtocolMessage);

                messages[0].header = [];

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    describe(`F-3

        Get three registration requests, and for each respond with registration response with "fcParams" set to "undefined", "null" and "empty" DOMString, correspondingly. Server must reject every response.  

    `, () => {
        it('fcParams is undefined', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);

                    messages[0].fcParams = undefined;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('fcParams is null', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);

                    messages[0].fcParams = null;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('fcParams is empty DOMString', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);

                    messages[0].fcParams = '';

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-4

        Get registration request, and generate registration response with "fcParams" NOT encoded in base64url, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let messages = tryDecodeJSON(success.uafProtocolMessage);

                messages[0].fcParams = messages[0].fcParams + '==';

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-5

        Get registration request, and generate registration response with "fcParams" set to type of NOT A DOMString, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let messages = tryDecodeJSON(success.uafProtocolMessage);

                messages[0].fcParams = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    describe(`F-6

        Get three registration requests, and for each respond with registration response with "assertions" set to "undefined", "null" and "empty" SEQUENCE, correspondingly. Server must reject every response. 

    `, () => {
        it('assertions is undefined', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);

                    messages[0].assertions = undefined;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('assertions is null', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);

                    messages[0].assertions = null;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('assertions is empty SEQUENCE', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);

                    messages[0].assertions = [];

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-7

        Get registration request, and generate registration response with "assertions" set to type of NOT A SEQUENCE, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let messages = tryDecodeJSON(success.uafProtocolMessage);

                messages[0].assertions = {};

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })
})
