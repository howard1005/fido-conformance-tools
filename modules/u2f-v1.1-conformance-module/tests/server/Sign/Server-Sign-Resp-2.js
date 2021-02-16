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

        Server-Sign-Resp-2

        Test server processing clientData

    `, function() {

    this.timeout(10000);
    // this.retries(3);

    let serverURL = window.config.test.serverURL;
    let U2FAuthr  = new window.CTAP.U2FClient(serverURL);

    let registerIdentity = () => {
        let identity   = generateRandomIdentity()
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                return registerResponse(authrResponse)
            })
            .then(() => {
                return identity
            })
    }


/* ---------- Negative Tests ---------- */
    describe(`F-1
            
        Send a Sign response, with clientData "typ" is null and undefined, and check that server returns an error

    `, () => {
        it('"typ" is null', function() {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONTypMissing": true})
                })
                .then((authrResponse) => {
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })

        it('"typ" is undefined', function() {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONTypNull": true})
                })
                .then((authrResponse) => {
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })
    })

    it(`F-2
            
        Send a Sign response, with "clientData.typ" not of type DOMString, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONTypInvalid": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-3
            
        Send a Sign response, with "clientData.typ" is empty, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONTypEmpty": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-4
            
        Send a Sign response, with "clientData.typ" is not "navigator.id.finishEnrollment", and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONTypNotCreate": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-5
            
        Send a Sign response, with "clientData.typ" is "navigator.id.getAssertion", and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONTypGet": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })


    describe(`F-6
            
        Send a Sign response, clientData "challenge" is null and undefined, and check that server returns an error

    `, () => {
        it('"challenge" is null', function() {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONChallengeMissing": true})
                })
                .then((authrResponse) => {
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })

        it('"challenge" is undefined', function() {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONChallengeNull": true})
                })
                .then((authrResponse) => {
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })
    })

    it(`F-7
            
        Send a Sign response, with "clientData.challenge" not of type DOMString, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONChallengeInvalid": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-8
            
        Send a Sign response, with "clientData.challenge" is empty, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONChallengeEmpty": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-9
            
        Send a Sign response, with "clientData.challenge" does not match requested challenge, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONChallengeNotMatching": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    describe(`F-10
            
        Send a Sign response, clientData "origin" is null and undefined, and check that server returns an error

    `, () => {
        it('"origin" is null', function() {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONOriginMissing": true})
                })
                .then((authrResponse) => {
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })

        it('"origin" is undefined', function() {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONOriginNull": true})
                })
                .then((authrResponse) => {
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })
    })

    it(`F-11
            
        Send a Sign response, with "clientData.origin" not of type DOMString, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONOriginInvalid": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-12
            
        Send a Sign response, with "clientData.origin" is empty, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONOriginEmpty": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-13
            
        Send a Sign response, with "clientData.origin" does not match origin of the requester, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"clientDataJSONOriginNotMatching": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })
})
