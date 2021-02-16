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

        Server-Sign-Req-1

        Test server generating U2F sign request

    `, function() {

    this.timeout(10000);
    // this.retries(3);

    let serverURL = window.config.test.serverURL;
    let U2FAuthr = new window.CTAP.U2FClient(serverURL);

/* ---------- Positive Tests ---------- */
    it(`P-1
            
         Perform a valid Register flow. Extract keyHandle from the attestation. Request Sign request from the server and check that:
            a) "status" is of type DOMString and set to "ok"
            b) "errorMessage" is of type DOMString and is empty
            c) "appId" is of type DOMString
            d) "keyHandle" is of type DOMString and is base64url encoded
            e) "challenge" is of type DOMString and is base64url encoded
            f) "registeredKeys" is a sequence of RegisteredKey. Must not be empty. For each RegisteredKey check that:
                1) Check that "version" is of type DOMString, and is set to "U2F_V2"
                2) Check that "keyHandle" is a base64url DOMString, and is set to previously registered credential

    `, () => {
        let identity   = generateRandomIdentity()
        let keyHandles = [];
        return getRegister(identity)
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                keyHandles.push(parseCTAP1RegistrationResponse(base64url.decode(authrResponse.registrationData)).KEYHANDLE);
                return registerResponse(authrResponse)
            })
            .then(() => {
                return getRegister(identity)
            })
            .then((response) => {
                return U2FAuthr.register(response.appId, response.registerRequests, response.registeredKeys)
            })
            .then((authrResponse) => {
                keyHandles.push(parseCTAP1RegistrationResponse(base64url.decode(authrResponse.registrationData)).KEYHANDLE);
                return registerResponse(authrResponse)
            })
            .then(() => {
                return getSign(identity)
            })
            .then((response) => {
                keyHandles = keyHandles.map(base64url.encode);

                assert.strictEqual(response.status, 'ok', 'Expected server response to return status code OK');
                assert.strictEqual(response.errorMessage, '', 'Expected "errorMessage" to be an empty string!');
                assert.isEmpty(response.errorMessage, '', 'Expected "errorMessage" to be an empty string!');
                
                assert.isString(response.appId, 'Expected "appId" to be a string!');

                assert.isString(response.challenge, 'Expected "challenge" to be of type String');
                assert.isNotEmpty(response.challenge, 'Expected "challenge" not to be empty!');
                assert.match(response.challenge, /^[a-zA-Z0-9_-]+$/, 'Expected "challenge" to be base64URL(without padding) encoded!');

                assert.isArray(response.registeredKeys, 'Expected "registeredKeys" to be a Array!');
                assert.isNotEmpty(response.registeredKeys, 'Expected "registeredKeys" not to be empty!');
                assert.strictEqual(response.registeredKeys.length, 2, 'Only two credential was registered, so only two credential expected!');

                let previousIndexOf = undefined;
                for(let registeredKey of response.registeredKeys) {
                    assert.isString(registeredKey.version, 'Expected "registeredKey.version" to be of type String');
                    assert.strictEqual(registeredKey.version, 'U2F_V2', 'Expected "registeredKey.version" to be set to "U2F_V2"!');
                    assert.isString(registeredKey.keyHandle, 'Expected "registeredKey.keyHandle" to be of type String');
                    assert.isNotEmpty(registeredKey.keyHandle, 'Expected "registeredKey.keyHandle" not to be empty!');
                    assert.match(registeredKey.keyHandle, /^[a-zA-Z0-9_-]+$/, 'Expected "registeredKey.keyHandle" to be base64URL(without padding) encoded!');

                    let khIndexOf = keyHandles.indexOf(registeredKey.keyHandle);

                    assert.isTrue(khIndexOf !== -1 && khIndexOf !== previousIndexOf, 'Server returned unknown keyHandle or keyHandle is repeated!');

                    previousIndexOf = khIndexOf;
                }

                if(response.timeout) {
                    assert.isNumber(response.timeout, 'Expected "timeout" to be a Number!');
                }
            })
    })
})
