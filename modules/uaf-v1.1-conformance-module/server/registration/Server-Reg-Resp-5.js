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

        Server-Reg-Resp-5

        Test server processing of the registration response message assertion dictionary

    `, function() {

    this.timeout(5000);
    this.retries(3);

/* ---------- Negative Tests ---------- */
    describe(`F-1

        Get three registration requests, and for each respond with registration response with "assertions[].assertion" set to "undefined", "null" and "empty" string, correspondingly. Server must reject every response.   

    `, () => {
        it('assertion is undefined', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertion = undefined

                    let uafResponse = JSON.stringify(messages)

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('assertion is null', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertion = null

                    let uafResponse = JSON.stringify(messages)

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('assertion is empty DOMString', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertion = '';

                    let uafResponse = JSON.stringify(messages)

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-2

        Get registration request, and generate registration response with "assertions[].assertion" is NOT base64url encoded, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].assertions[0].assertion = messages[0].assertions[0].assertion + '==';

                let uafResponse = JSON.stringify(messages)

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-3

        Get registration request, and generate registration response with "assertions[].assertion" set to type of NOT A DOMString, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].assertions[0].assertion = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    describe(`F-4

        Get three registration requests, and for each respond with registration response with "assertions[].assertionScheme" set to "undefined", "null" and "empty" string, correspondingly. Server must reject every response. 

    `, () => {
        it('assertionScheme is undefined', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertionScheme = 0xdeadbeef

                    let uafResponse = JSON.stringify(messages)

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('assertionScheme is null', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertionScheme = null

                    let uafResponse = JSON.stringify(messages)

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('assertionScheme is empty DOMString', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertionScheme = '';

                    let uafResponse = JSON.stringify(messages)

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-5

        Get registration request, and generate registration response with "assertions[].assertionScheme" set to type of NOT A DOMString, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].assertions[0].assertionScheme = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-6

        Get registration request, and generate registration response with "assertions[].assertionScheme" set NOT to "UAFV1TLV", and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].assertions[0].assertionScheme = 'NOTUAFV1TLV';

                let uafResponse = JSON.stringify(messages)

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-7

        Get registration request, and generate registration response with "assertions[].tcDisplayPNGCharacteristics" set to type of NOT A SEQUENCE, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].assertions[0].tcDisplayPNGCharacteristics = {};

                let uafResponse = JSON.stringify(messages)

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-8

        Get registration request, and generate registration response with "assertions[].exts" set to type of NOT A SEQUENCE, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                
                messages[0].assertions[0].exts = {};

                let uafResponse = JSON.stringify(messages)

                return rest.register.post(uafResponse, 1498, username)
            })
    })
})
