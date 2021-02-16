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

        Server-Register-Resp-1

        Test server processing authenticator responses

    `, function() {

    this.timeout(10000);
    // this.retries(3);

    let identity  = generateRandomIdentity()

    let serverURL = window.config.test.serverURL;
    let U2FAuthr  = new window.CTAP.U2FClient(serverURL);

/* ---------- Positive Tests ---------- */
    it(`P-1
            
        Send a valid Registration response, and check that server succeeds

    `, () => {
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                return registerResponse(authrResponse)
            })
    })

    it(`P-2
            
        Send a valid register request, and check that server successfully returns response. Generate a valid register response, and check that server succeeds. Send another register request and check that server returns response, containing "registeredKeys" sequence, that is not empty, and contains previously registered keyHandle.

    `, () => {
        let identity  = generateRandomIdentity()
        let keyHandle = undefined;
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                keyHandle = parseCTAP1RegistrationResponse(base64url.decode(authrResponse.registrationData)).KEYHANDLE;
                return registerResponse(authrResponse)
            })
            .then(() => {
                return getRegister(identity)
            })
            .then((response) => {
                assert.isArray(response.registeredKeys, 'Expected "registeredKeys" to be a Array!');
                assert.isNotEmpty(response.registeredKeys, 'Expected "registeredKeys" to not to be empty!');
                assert.strictEqual(response.registeredKeys.length, 1, 'Expected to get exactly 1 registered key, as only one registration was performed!');
                assert.isObject(response.registeredKeys[0], 'Expected registeredKey to be a Dictionary!');
                assert.strictEqual(response.registeredKeys[0].version, 'U2F_V2', 'Expected version to be set to "U2F_V2"!');
                assert.strictEqual(response.registeredKeys[0].keyHandle, base64url.encode(keyHandle), 'Expected registeredKeys to contain previously registered keyHandle!');
            })
    })

/* ---------- Negative Tests ---------- */
    describe(`F-1
            
        Send a Registration response, with "version" field set to null and undefined, and check that server returns an error

    `, () => {
        it('"version" is null', function() {
            let identity = generateRandomIdentity()
            return getRegister(identity)
                .then((response) => {
                    return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.version = null;
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })

        it('"version" is undefined', function() {
            let identity = generateRandomIdentity()
            return getRegister(identity)
                .then((response) => {
                    return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.version = undefined;
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })
    })

    it(`F-2
            
        Send a Registration response, with "version" not of type DOMString, and check that server returns an error

    `, () => {
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.version = generateRandomTypeExcluding('string');
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-3
            
        Send a Registration response, with "version" set to a random string, and check that server returns an error

    `, () => {
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.version = generateRandomString();
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    describe(`F-4
            
        Send a Registration response, with "registrationData" field set to null and undefined, and check that server returns an error

    `, () => {
        it('"registrationData" is null', function() {
            let identity = generateRandomIdentity()
            return getRegister(identity)
                .then((response) => {
                    return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.registrationData = null;
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })

        it('"registrationData" is undefined', function() {
            let identity = generateRandomIdentity()
            return getRegister(identity)
                .then((response) => {
                    return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.registrationData = undefined;
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })
    })

    it(`F-5
            
        Send a Registration response, with "registrationData" not of type DOMString, and check that server returns an error

    `, () => {
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.registrationData = generateRandomTypeExcluding('string');
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-6
            
        Send a Registration response, with "registrationData" set to a random string, and check that server returns an error

    `, () => {
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.registrationData = generateRandomString();
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    describe(`F-7
            
        Send a Registration response, with "clientData" field set to null and undefined, and check that server returns an error

    `, () => {
        it('"clientData" is null', function() {
            let identity = generateRandomIdentity()
            return getRegister(identity)
                .then((response) => {
                    return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.clientData = null;
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })

        it('"clientData" is undefined', function() {
            let identity = generateRandomIdentity()
            return getRegister(identity)
                .then((response) => {
                    return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
                })
                .then((authrResponse) => {
                    authrResponse.clientData = undefined;
                    return expectPromiseToFail(registerResponse(authrResponse))
                })
        })
    })

    it(`F-8
            
        Send a Registration response, with "clientData" not of type DOMString, and check that server returns an error

    `, () => {
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.clientData = generateRandomTypeExcluding('string');
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-9
            
        Send a Registration response, with "clientData" set to a random string, and check that server returns an error

    `, () => {
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                authrResponse.clientData = generateRandomString();
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })
})
