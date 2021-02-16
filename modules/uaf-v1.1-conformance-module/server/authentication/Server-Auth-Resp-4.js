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

        Server-Auth-Resp-4

        Test server processing of the authentication response message FinalChallengeParams

    `, function() {

    this.timeout(5000);
    this.retries(3);

/* ---------- Negative Tests ---------- */
    describe(`F-1

        Get three authentication requests, and for each respond with authentication response with "FinalChallengeParams.appID" set to "undefined", "null" and "empty" DOMString, correspondingly. Server must reject every response.    

    `, () => {
        it('FinalChallengeParams.appID is undefined', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomAppIDEnabled': true,
                'fcParamsCustomAppID': undefined
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })

        it('FinalChallengeParams.appID is undefined', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomAppIDEnabled': true,
                'fcParamsCustomAppID': null
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })

        it('FinalChallengeParams.appID is empty DOMString', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomAppIDEnabled': true,
                'fcParamsCustomAppID': ''
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })
    })

    it(`F-2

        Get authentication request, and generate authentication response with "FinalChallengeParams.appID" set to type of NOT A DOMString, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'fcParamsCustomAppIDEnabled': true,
            'fcParamsCustomAppID': 42
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    describe(`F-3

        Get three authentication requests, and for each respond with authentication response with "FinalChallengeParams.challenge" set to "undefined", "null" and "empty" DOMString, correspondingly. Server must reject every response.    

    `, () => {
        it('FinalChallengeParams.challenge is undefined', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomChallengeEnabled': true,
                'fcParamsCustomChallenge': undefined
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })

        it('FinalChallengeParams.challenge is undefined', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomChallengeEnabled': true,
                'fcParamsCustomChallenge': null
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })

        it('FinalChallengeParams.challenge is empty DOMString', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomChallengeEnabled': true,
                'fcParamsCustomChallenge': ''
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })
    })

    it(`F-4

        Get authentication request, and generate authentication response with "FinalChallengeParams.challenge" does NOT equal to AuthenticationRequest.challenge, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'fcParamsCustomChallengeEnabled': true,
            'fcParamsCustomChallenge': generateRandomString()
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-5

        Get authentication request, and generate authentication response with "FinalChallengeParams.challenge" set to type of NOT A DOMString, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'fcParamsCustomChallengeEnabled': true,
            'fcParamsCustomChallenge': 0xdeadbeef
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    describe(`F-6

        Get three authentication requests, and for each respond with authentication response with "FinalChallengeParams.facetID" set to "undefined", "null" and "empty" DOMString, correspondingly. Server must reject every response.  

    `, () => {
        it('FinalChallengeParams.facetID is undefined', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomFacetIDEnabled': true,
                'fcParamsCustomFacetID': undefined
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })

        it('FinalChallengeParams.facetID is undefined', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomFacetIDEnabled': true,
                'fcParamsCustomFacetID': null
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })

        it('FinalChallengeParams.facetID is empty DOMString', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomFacetIDEnabled': true,
                'fcParamsCustomFacetID': ''
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })
    })

    it(`F-7

        Get authentication request, and generate authentication response with "FinalChallengeParams.facetID" set to type of NOT A DOMString, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'fcParamsCustomFacetIDEnabled': true,
            'fcParamsCustomFacetID': 0xdeadbeef
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    describe(`F-8

        Get three authentication requests, and for each respond with authentication response with "FinalChallengeParams.channelBinding" set to "undefined", "null" and "empty" DICTIONARY, correspondingly. Server must reject every response.   

    `, () => {
        it('FinalChallengeParams.channelBinding is undefined', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomChannelBindingEnabled': true,
                'fcParamsCustomChannelBinding': undefined
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })

        it('FinalChallengeParams.channelBinding is undefined', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomChannelBindingEnabled': true,
                'fcParamsCustomChannelBinding': null
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })

        it('FinalChallengeParams.channelBinding is empty DOMString', () => {
            let username = generateRandomString();
            let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                'context': 'Auth',
                'fcParamsCustomChannelBindingEnabled': true,
                'fcParamsCustomChannelBinding': {}
            })

            return rest.register.get(1200, username)
                .then((messages) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(messages)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
                .then(() => rest.authenticate.get(1200, username))
                .then((success) => {
                    let UAFMessage = {
                        'uafProtocolMessage': JSON.stringify(success)
                    }

                    return authr.processUAFOperation(UAFMessage)
                })
                .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
        })
    })

    it(`F-9

        Get authentication request, and generate authentication response with "FinalChallengeParams.channelBinding" set to type of NOT A DICTIONARY, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'fcParamsCustomChannelBindingEnabled': true,
            'fcParamsCustomChannelBinding': 0xdeadbeef
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })
})
