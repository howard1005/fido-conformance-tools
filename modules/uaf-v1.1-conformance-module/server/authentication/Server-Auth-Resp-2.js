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

        Server-Auth-Resp-2

        Test server processing of the authentication response message DICTIONARY

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
            
        Get three authentication requests, and for each respond with authentication response with "header" set to "undefined", "null" and "empty" DICTIONARY, correspondingly. Server must reject every response.   

    `, () => {
        it('header is undefined', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header = undefined;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('header is null', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header = null;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('header is empty DICTIONARY', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].header = {};

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-2

        Get authentication request, and generate authentication response with "header" set to type of NOT A DICTIONARY, and send it to the server. Server must reject response. 

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
                
                messages[0].header = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    describe(`F-3

        Get three authentication requests, and for each respond with authentication response with "fcParams" set to "undefined", "null" and "empty" DICTIONARY, correspondingly. Server must reject every response. 

    `, () => {
        it('fcParams is undefined', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].fcParams = undefined;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('fcParams is null', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].fcParams = null;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('fcParams is empty DOMString', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].fcParams = '';

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-4

        Get authentication request, and generate authentication response with "fcParams" NOT encoded in base64url, and send it to the server. Server must reject response.  

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
                
                messages[0].fcParams = messages[0].fcParams + '==';

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-5

        Get authentication request, and generate authentication response with "fcParams" set to type of NOT A DOMString, and send it to the server. Server must reject response.    

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
                
                messages[0].fcParams = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    describe(`F-6

        Get three authentication requests, and for each respond with authentication response with "assertions" set to "undefined", "null" and "empty" SEQUENCE, correspondingly. Server must reject every response.   

    `, () => {
        it('assertions is undefined', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions = undefined;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('assertions is null', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions = null;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('assertions is empty SEQUENCE', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions = [];

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-7

        Get authentication request, and generate authentication response with "assertions" set to type of NOT A SEQUENCE, and send it to the server. Server must reject response.   

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
                
                messages[0].assertions = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })
})
