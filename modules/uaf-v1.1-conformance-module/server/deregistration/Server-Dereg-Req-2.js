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

        Server-Dereg-Req-2

        Test the DeregistrationRequest dictionary

    `, function() {

    let deregistrationRequest;
    before(() => {
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
            .then(() => rest.deregister.get(1200, username))
            .then((data) => {
                deregistrationRequest = data[0];
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    });

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        DeregistrationRequest MUST contain "header" field, of type Dictionary 

    `, () => {
        assert.isObject(deregistrationRequest.header, 'OperationHeader MUST be of type DICTIONARY');
    })

    it(`P-2

        DeregistrationRequest must contain "authenticators" field, of type SEQUENCE. Authenticators MUST not be empty.

    `, () => {
        assert.isArray(deregistrationRequest.authenticators, 'Authenticators MUST be of type SEQUENCE');
        assert.isNotEmpty(deregistrationRequest.authenticators, 'Authenticators MUST NOT be empty!');
    })
})