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

        Server-Reg-Resp-3

        Test server processing of the registration response message dictionary

    `, function() {

    this.timeout(5000);
    this.retries(3);

/* ---------- Negative Tests ---------- */
    describe(`F-1

        Get three registration requests, and for each respond with registration response with "header.op" set to "undefined", "null" and "empty" string, correspondingly. Server must reject every response.   

    `, () => {
        it('header.op is undefined', () => {
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

                    messages[0].header.op = undefined;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('header.op is null', () => {
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

                    messages[0].header.op = null;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('header.op is empty DOMString', () => {
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

                    messages[0].header.op = '';

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-2

        Get registration request, and generate registration response with "header.op" set to type of NOT A DOMString, and send it to the server. Server must reject response.  

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

                messages[0].header.op = {};

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    describe(`F-3

        Get two registration requests, and for each respond with registration response with "header.op" set to "REG" and "reg". Server must reject every response. 

    `, () => {
        it('header.op is "REG"', () => {
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

                    messages[0].header.op = 'REG';

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('header.op is "reg"', () => {
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

                    messages[0].header.op = 'reg';

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    describe(`F-4

        Get two registration requests, and for each respond with registration response with "header.op" set to "Auth" and "Dereg". Server must reject every response.    

    `, () => {
        it('header.op is "Auth"', () => {
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

                    messages[0].header.op = 'Auth';

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('header.op is "Dereg"', () => {
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

                    messages[0].header.op = 'Dereg';

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    describe(`F-5

        Get three registration requests, and for each respond with registration response with "header.upv" set to "undefined", "null" and "empty" dictionary, correspondingly. Server must reject every response.  

    `, () => {
        it('header.upv is undefined', () => {
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

                    messages[0].header.upv = undefined;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('header.upv is null', () => {
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

                    messages[0].header.upv = null;

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('header.upv is empty Dictionary', () => {
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

                    messages[0].header.upv = {};

                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-6

        Get registration request, and generate registration response with "header.upv" set to type of NOT A Dictionary, and send it to the server. Server must reject response.    

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

                messages[0].header.upv = [];

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-7

        Get registration request, and generate registration response with "header.upv" set to NOT v1.1({"major":1, "minor":7}), and send it to the server. Server must reject response.    

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

                messages[0].header.upv = {
                    'major': 1,
                    'minor': 7
                }

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-8

        Get registration request, and generate registration response with "header.appID" set to type of NOT A DOMString, and send it to the server. Server must reject response.   

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

                messages[0].header.appID = 0xdeadbeef

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-9

        Get registration request, and generate registration response with "header.serverData" set to type of NOT A DOMString, and send it to the server. Server must reject response.   

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

                messages[0].header.serverData = 0xdeadbeef

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-10

        Get registration request, and generate registration response with "header.exts" set to type of NOT A SEQUENCE, and send it to the server. Server must reject response.  

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

                messages[0].header.exts = '[]';

                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })
})
