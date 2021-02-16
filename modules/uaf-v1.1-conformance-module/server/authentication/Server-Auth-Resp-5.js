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

        Server-Auth-Resp-5

        Test server processing of the registration response message assertion DICTIONARY

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

        Get three authentication requests, and for each respond with authentication response with "assertions[].assertion" set to "undefined", "null" and "empty" DOMString, correspondingly. Server must reject every response.    

    `, () => {
        it('Assertion.assertion is undefined', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertion = undefined;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('Assertion.assertion is null', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertion = null;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('Assertion.assertion is empty DOMString', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertion = '';

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-2

        Get authentication request, and generate authentication response with "assertions[].assertion" is NOT base64url encoded, and send it to the server. Server must reject response.    

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
                
                messages[0].assertions[0].assertion = messages[0].assertions[0].assertion + '==';

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-3

        Get authentication request, and generate authentication response with "assertions[].assertion" set to type of NOT A DOMString, and send it to the server. Server must reject response.  

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
                
                messages[0].assertions[0].assertion = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    describe(`F-4

        Get three authentication requests, and for each respond with authentication response with "assertions[].assertionScheme" set to "undefined", "null" and "empty" DOMString, correspondingly. Server must reject every response.  

    `, () => {
        it('Assertion.assertionScheme is undefined', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertionScheme = undefined;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('Assertion.assertionScheme is null', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertionScheme = null;

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })

        it('Assertion.assertionScheme is empty DOMString', () => {
            return rest.authenticate.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((data) => {
                    let messages = tryDecodeJSON(data.uafProtocolMessage);
                    
                    messages[0].assertions[0].assertionScheme = '';

                    let uafResponse = JSON.stringify(messages)

                    return rest.authenticate.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-5

        Get authentication request, and generate authentication response with "assertions[].assertionScheme" set to type of NOT A DOMString, and send it to the server. Server must reject response.    

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
                
                messages[0].assertions[0].assertionScheme = 0xdeadbeef;

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-6

        Get authentication request, and generate authentication response with "assertions[].assertionScheme" set NOT to "UAFV1TLV", and send it to the server. Server must reject response. 

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
                
                messages[0].assertions[0].assertionScheme = 'DEFINETLYNOTUAFV1TLV';

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-7

        Get authentication request, and generate authentication response with "assertions[].exts" set to type of NOT A SEQUENCE, and send it to the server. Server must reject response.    

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
                
                messages[0].assertions[0].exts = 'The EXPENDABLES!';

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })
})
