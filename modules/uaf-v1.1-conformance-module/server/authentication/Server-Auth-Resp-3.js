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

        Server-Auth-Resp-3

        Test server processing of the authentication response operation header DICTIONARY

    `, function() {

    let username = generateRandomString();
    let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
    before(() => {
        
        return rest.register.get(1200, username)
            .then((response) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => rest.register.post(data.uafProtocolMessage, 1200, username))
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

    this.timeout(5000);
    this.retries(3);

/* ---------- Negative Tests ---------- */
    describe(`F-1

        Get three authentication requests, and for each respond with authentication response with "header.op" set to "undefined", "null" and "empty" DOMString, correspondingly. Server must reject every response.    

    `, () => {
        it('header.op is undefined', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.op = undefined;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('header.op is null', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.op = null;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('header.op is empty DOMString', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.op = '';

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-2

        Get authentication request, and generate authentication response with "header.op" set to type of NOT A DOMString, and send it to the server. Server must reject response.  

    `, () => {
        return rest.authenticate.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].header.op = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    describe(`F-3

        Get two authentication requests, and for each respond with authentication response with "header.op" set to "AUTH" and "auth". Server must reject every response.

    `, () => {
        it('header.op is AUTH', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.op = 'AUTH';

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('header.op is auth', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.op = 'auth';

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })
    })

    describe(`F-4

        Get two authentication requests, and for each respond with authentication response with "header.op" set to "Reg" and "Dereg". Server must reject every response.   

    `, () => {
        it('header.op is Reg', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.op = 'Reg';

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('header.op is Dereg', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.op = 'Dereg';

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })
    })

    describe(`F-5

        Get three authentication requests, and for each respond with authentication response with "header.upv" set to "undefined", "null" and "empty" DICTIONARY, correspondingly. Server must reject every response.  

    `, () => {
        it('header.upv is undefined', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.upv = undefined;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('header.upv is null', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.upv = null;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('header.upv is empty DICTIONARY', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header.upv = {};

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-6

        Get authentication request, and generate authentication response with "header.upv" set to type of NOT A DICTIONARY, and send it to the server. Server must reject response.    

    `, () => {
        return rest.authenticate.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].header.upv = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-7

        Get authentication request, and generate authentication response with "header.upv" set to NOT v1.1({"major":1, "minor":0}), and send it to the server. Server must reject response.    

    `, () => {
        return rest.authenticate.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].header.upv = {
                    'major': 1,
                    'minor': 7
                }

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-8

        Get authentication request, and generate authentication response with "header.appID" set to type of NOT A DOMString, and send it to the server. Server must reject response.   

    `, () => {
        return rest.authenticate.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].header.appID = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-9

        Get authentication request, and generate authentication response with "header.serverData" set to type of NOT A DOMString, and send it to the server. Server must reject response.  

    `, () => {
        return rest.authenticate.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].header.serverData = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-10

        Get authentication request, and generate authentication response with "header.exts" set to type of NOT A SEQUENCE, and send it to the server. Server must reject response. 

    `, () => {
        return rest.authenticate.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].header.exts = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })
})
