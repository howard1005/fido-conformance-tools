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

        Server-Dereg-Req-4

        Test the Authenticator Dictionary

    `, function() {

    let authenticators;
    let authenticatorAAID = 'FFFF#FC01';
    before(() => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((response) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, authenticatorAAID)
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.deregister.get(1200, username))
            .then((data) => {
                authenticators = data[0].authenticators;
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    });

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        For each DeregisterAuthenticator in "authenticators" sequence: "aaid" field must be of type DOMString, nine(9) characters long, and it must match /^[0-9A-Fa-f]{4}#[0-9A-Fa-f]{4}$/ regex pattern.  

    `, () => {
        for(let DeregisterAuthenticator of authenticators) {
            assert.isString(DeregisterAuthenticator.aaid, 'aaid MUST be of type DOMString!');
            assert.isTrue(DeregisterAuthenticator.aaid.length === 9, 'aaid MUST be 9 characters long!');
            assert.match(DeregisterAuthenticator.aaid, /^[a-fA-F0-9]{4}#[a-fA-F0-9]{4}$/, `aaid ${DeregisterAuthenticator.aaid} is not in format {2 byte encoded in HEX}#{2 byte encoded in HEX}!`);
        }
    })

    it(`P-2

        For each DeregisterAuthenticator in "authenticators" sequence: "keyID" field must be of type DOMString, and: 
            (a) it must be base64url encoded 
            (b) it must be more than 43 characters(32 bytes) long 
            (c) it must be less than 2731 characters(2048 bytes) long

    `, () => {
        for(let DeregisterAuthenticator of authenticators) {
            assert.isString(DeregisterAuthenticator.keyID, 'keyID MUST be of type DOMString!');
            assert.match(DeregisterAuthenticator.keyID, /^[a-zA-Z0-9_-]+$/, 'keyID MUST be base64URL(without padding) encoded!');
            assert.isAtLeast(DeregisterAuthenticator.keyID.length, 1, 'keyID MUST be at least 1 character long!');
            assert.isAtMost(DeregisterAuthenticator.keyID.length, 1536, 'keyID can be max of 1536 characters long!');
        }
    })

    it(`P-3

        Request deregistration for all assertions for a single authenticator specified by an AAID, and check that server returns deregistration request with "DeregisterAuthenticator.aaid" set to specified AAID, and "DeregisterAuthenticator.keyID" set to "empty" DOMString.

    `, () => {
        let username = generateRandomString();
        let aaid = 'FFFF#FC01';
        return rest.register.get(1200, username)
            .then((response) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, aaid)
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.deregister.get(1200, username, {
                'deregisterAAID': aaid
            }))
            .then((data) => {
                let authenticators = data[0].authenticators;
                let expectedResult = {'aaid': aaid, 'keyID': ''};
                assert.deepInclude(authenticators, expectedResult, `Server was requested to deregister all keys for ${aaid} aaid. Expected authenticators field(${JSON.stringify(authenticators, null, 4)}) to contain DeregisterAuthenticator with aaid set to ${aaid} and keyID set to empty DOMString(${JSON.stringify(expectedResult, null, 4)})`);
            })
    })

    it(`P-4

        Request deregistration for all assertions for all authenticators, and check that server returns DeregistrationRequest with "DeregisterAuthenticator.aaid" and "DeregisterAuthenticator.keyID" set to "empty" DOMString. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((response) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.deregister.get(1200, username, {
                'deregisterAll': true
            }))
            .then((data) => {
                let authenticators = data[0].authenticators;
                let expectedResult = {'aaid': '', 'keyID': ''};

                assert.deepInclude(authenticators, expectedResult, `Server was requested to deregister all authenticators. Expected authenticators field(${JSON.stringify(authenticators, null, 4)}) to contain DeregisterAuthenticator with aaid and keyID set to empty DOMStrings(${JSON.stringify(expectedResult, null, 4)})`);
            })
    })
})
