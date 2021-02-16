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

        Server-Sign-Resp-3

        Test server processing signatureData

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


/* ---------- Positive Tests ---------- */
    it(`P-1
            
         Perform a valid Register flow, send two consecutive Sign flows, and check that server succeeds 

    `, () => {
        let userIdentity = undefined;
        return registerIdentity()
            .then((identity) => {
                userIdentity = identity;
                return getSign(userIdentity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                return signResponse(authrResponse)
            })
            .then(() => {
                return getSign(userIdentity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                return signResponse(authrResponse)
            })
    })

/* ---------- Negative Tests ---------- */
    it(`F-1
            
        Send a Sign response, with UP flag is 0, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"noUP": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-2
            
        Perform two Sign flows, with counter not increased, and check that server returns an error

    `, () => {
        let userIdentity = undefined;
        return registerIdentity()
            .then((identity) => {
                userIdentity = identity
                return getSign(userIdentity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys)
            })
            .then((authrResponse) => {
                return signResponse(authrResponse)
            })
            .then(() => {
                return getSign(userIdentity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"counterDidNotIncrease": true})
            })
            .then((authrResponse) => {
                return signResponse(authrResponse)
            })
    })

    it(`F-3
            
        Send a Sign response, with bad signature, and check that server returns an error

    `, () => {
        return registerIdentity()
            .then((identity) => {
                return getSign(identity)
            })
            .then((response) => {
                return U2FAuthr.sign(response.appId, response.challenge, response.registeredKeys, {"badSignature": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })
})
