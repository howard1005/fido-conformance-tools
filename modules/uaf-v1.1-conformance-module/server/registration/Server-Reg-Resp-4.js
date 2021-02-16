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

        Server-Reg-Resp-4

        Test server processing of the registration response message FinalChallengeParams

    `, function() {

    this.timeout(5000);
    this.retries(3);

/* ---------- Negative Tests ---------- */

    describe(`F-1

        Get three registration requests, and for each respond with registration response with "FinalChallengeParams.appID" set to "undefined", "null" and "empty" string, correspondingly. Server must reject every response.   

    `, () => {
        it('FinalChallengeParams.appID is undefined', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomAppIDEnabled': true,
                        'fcParamsCustomAppID': undefined
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('FinalChallengeParams.appID is null', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomAppIDEnabled': true,
                        'fcParamsCustomAppID': null
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('FinalChallengeParams.appID is empty DOMString', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomAppIDEnabled': true,
                        'fcParamsCustomAppID': ''
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-2

        Get registration request, and generate registration response with "FinalChallengeParams.appID" set to type of NOT A DOMString, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'fcParamsCustomAppIDEnabled': true,
                    'fcParamsCustomAppID': 0xdeadbeef
                });

                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let messages = tryDecodeJSON(success.uafProtocolMessage);
                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    describe(`F-3

        Get three registration requests, and for each respond with registration response with "FinalChallengeParams.challenge" set to "undefined", "null" and "empty" string, correspondingly. Server must reject every response.   

    `, () => {
        it('FinalChallengeParams.challenge is undefined', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomChallengeEnabled': true,
                        'fcParamsCustomChallenge': undefined
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('FinalChallengeParams.challenge is null', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomChallengeEnabled': true,
                        'fcParamsCustomChallenge': null
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('FinalChallengeParams.challenge is empty DOMString', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomChallengeEnabled': true,
                        'fcParamsCustomChallenge': ''
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-4

        Get registration request, and generate registration response with "FinalChallengeParams.challenge" does NOT equal to RegistrationRequest.challenge, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'fcParamsCustomChallengeEnabled': true,
                    'fcParamsCustomChallenge': generateRandomString()
                });

                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let messages = tryDecodeJSON(success.uafProtocolMessage);
                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-5
        
        Get registration request, and generate registration response with "FinalChallengeParams.challenge" set to type of NOT A DOMString, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'fcParamsCustomChallengeEnabled': true,
                    'fcParamsCustomChallenge': 0xdeadbeef
                });

                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let messages = tryDecodeJSON(success.uafProtocolMessage);
                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    describe(`F-6

        Get three registration requests, and for each respond with registration response with "FinalChallengeParams.facetID" set to "undefined", "null" and "empty" string, correspondingly. Server must reject every response. 

    `, () => {
        it('FinalChallengeParams.facetID is undefined', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomFacetIDEnabled': true,
                        'fcParamsCustomFacetID': undefined
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('FinalChallengeParams.facetID is null', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomFacetIDEnabled': true,
                        'fcParamsCustomFacetID': null
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('FinalChallengeParams.facetID is empty Dictionary', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomFacetIDEnabled': true,
                        'fcParamsCustomFacetID': {}
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-7

        Get registration request, and generate registration response with "FinalChallengeParams.facetID" set to type of NOT A DOMString, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'fcParamsCustomFacetIDEnabled': true,
                    'fcParamsCustomFacetID': 0xdeadbeef
                });

                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let messages = tryDecodeJSON(success.uafProtocolMessage);
                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    describe(`F-8

        Get three registration requests, and for each respond with registration response with "FinalChallengeParams.channelBinding" set to "undefined", "null" and "empty" string, correspondingly. Server must reject every response.  

    `, () => {
        it('FinalChallengeParams.channelBinding is undefined', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomChannelBindingEnabled': true,
                        'fcParamsCustomChannelBinding': undefined
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('FinalChallengeParams.channelBinding is null', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomChannelBindingEnabled': true,
                        'fcParamsCustomChannelBinding': null
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })

        it('FinalChallengeParams.channelBinding is empty Dictionary', () => {
            let username = generateRandomString();
            return rest.register.get(1200, username)
                .then((messages) => {
                    let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                        'context': 'Reg',
                        'fcParamsCustomChannelBindingEnabled': true,
                        'fcParamsCustomChannelBinding': {}
                    });

                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => {
                    let messages = tryDecodeJSON(success.uafProtocolMessage);
                    let uafResponse = JSON.stringify(messages);

                    return rest.register.post(uafResponse, 1498, username)
                })
        })
    })

    it(`F-9

        Get registration request, and generate registration response with "FinalChallengeParams.channelBinding" set to type of NOT A Dictionary, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'fcParamsCustomChannelBindingEnabled': true,
                    'fcParamsCustomChannelBinding': 0xdeadbeef
                });

                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let messages = tryDecodeJSON(success.uafProtocolMessage);
                let uafResponse = JSON.stringify(messages);

                return rest.register.post(uafResponse, 1498, username)
            })
    })
})
