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

        Server-Register-Resp-3

        Test server processing registrationData

    `, function() {

    this.timeout(10000);
    // this.retries(3);

    let identity  = generateRandomIdentity()

    let serverURL = window.config.test.serverURL;
    let U2FAuthr  = new window.CTAP.U2FClient(serverURL);

// /* ---------- Negative Tests ---------- */
    it(`F-1

        Send a Registration response, with attestation containing bad RFU, and check that server returns an error

    `, () => {
        let identity  = generateRandomIdentity()
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys, {"badRFU": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-2
            
        Send a Registration response, with attestation containing bad keyHandle, and check that server returns an error

    `, () => {
        let identity  = generateRandomIdentity()
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys, {"badKeyHandle": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-3
            
        Send a Registration response, with attestation containing bad Reserver Byte, and check that server returns an error

    `, () => {
        let identity  = generateRandomIdentity()
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys, {"badReserveByte": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-4

        Send a Registration response, with attestation containing bad Signature, and check that server returns an error

    `, () => {
        let identity  = generateRandomIdentity()
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys, {"badSignature": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })

    it(`F-5

        Send a Registration response, with attestation containing bad Attestation cert, and check that server returns an error

    `, () => {
        let identity  = generateRandomIdentity()
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys, {"badAttestationCert": true})
            })
            .then((authrResponse) => {
                return expectPromiseToFail(registerResponse(authrResponse))
            })
    })
})
