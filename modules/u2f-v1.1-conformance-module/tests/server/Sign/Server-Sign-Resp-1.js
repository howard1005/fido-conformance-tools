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

        Server-Sign-Resp-1

        Test server processing sign response

    `, function() {

    this.timeout(10000);
    // this.retries(3);

    let serverURL = window.config.test.serverURL;
    let U2FAuthr = new window.CTAP.U2FClient(serverURL);

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

/* ---------- Positive Tests ---------- */
    it(`P-1
            
         Perform a valid Register flow, and get Sign request, generate a valid Sign response, send it to server, and check that server succeeds

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                return signResponse(authrResponse)
            })
    })

/* ---------- Positive Tests ---------- */
    describe(`F-1
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with keyHandle is undefined and null, send it to server, and check that server reuturns an error

    `, () => {
        it('"keyHandle" is null', () => {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.keyHandle = null;
                    return expectPromiseToFail(signResponse(authrResponse))
                })
        })

        it('"keyHandle" is undefined', () => {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.keyHandle = undefined;
                    return expectPromiseToFail(signResponse(authrResponse))
                })
        })
    })

    it(`F-2
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with keyHandle is empty string, send it to server, and check that server reuturns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.keyHandle = "";
                return expectPromiseToFail(signResponse(authrResponse))
            })
    })

    it(`F-3
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with keyHandle set to an unknown KeyHandle, send it to server, and check that server reuturns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.keyHandle = generateRandomString();
                return expectPromiseToFail(signResponse(authrResponse))
            })
    })

    it(`F-4
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with keyHandle not of type DOMString, send it to server, and check that server reuturns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.keyHandle = generateRandomTypeExcluding('string');
                return expectPromiseToFail(signResponse(authrResponse))
            })
    })

    describe(`F-5
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with signatureData is undefined and null, send it to server, and check that server reuturns an error

    `, () => {
        it('"signatureData" is null', () => {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.signatureData = null;
                    return expectPromiseToFail(signResponse(authrResponse))
                })
        })

        it('"signatureData" is undefined', () => {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.signatureData = undefined;
                    return expectPromiseToFail(signResponse(authrResponse))
                })
        })
    })

    it(`F-6
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with signatureData is empty string, send it to server, and check that server reuturns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.signatureData = "";
                return expectPromiseToFail(signResponse(authrResponse))
            })
    })

    it(`F-7
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with signatureData set to an unknown signatureData, send it to server, and check that server reuturns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.signatureData = generateRandomString();
                return expectPromiseToFail(signResponse(authrResponse))
            })
    })

    it(`F-8
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with clientData not of type DOMString, send it to server, and check that server reuturns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.clientData = generateRandomTypeExcluding('string');
                return expectPromiseToFail(signResponse(authrResponse))
            })
    })

    describe(`F-9
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with clientData is undefined and null, send it to server, and check that server reuturns an error

    `, () => {
        it('"clientData" is null', () => {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.clientData = null;
                    return expectPromiseToFail(signResponse(authrResponse))
                })
        })

        it('"clientData" is undefined', () => {
            return registerIdentity()
                .then((identity) => {
                    return getSign(identity)
                })
                .then((response) => {
                    return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.clientData = undefined;
                    return expectPromiseToFail(signResponse(authrResponse))
                })
        })
    })

    it(`F-10
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with clientData is empty string, send it to server, and check that server reuturns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.clientData = "";
                return expectPromiseToFail(signResponse(authrResponse))
            })
    })

    it(`F-11
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with clientData set to an unknown clientData, send it to server, and check that server reuturns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.clientData = generateRandomString();
                return expectPromiseToFail(signResponse(authrResponse))
            })
    })

    it(`F-12
            
         Perform a valid Register flow, and get Sign request, generate a Sign response, with clientData not of type DOMString, send it to server, and check that server reuturns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.clientData = generateRandomTypeExcluding('string');
                return expectPromiseToFail(signResponse(authrResponse))
            })
    })
})
