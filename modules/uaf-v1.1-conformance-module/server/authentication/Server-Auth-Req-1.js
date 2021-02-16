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

        Server-Auth-Req-1

        Test the DeregistrationRequest SEQUENCE

    `, function() {

    let uafMessages = undefined;
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
            .then((success) => rest.authenticate.get(1200, username))
            .then((messages) => {
                uafMessages = messages;
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        AuthenticationRequest SEQUENCE must not contain two dictionaries of the same protocol version

    `, () => {
        let foundVersion = false;

        for (let message of uafMessages) {
            if(message.header.upv.major === 1 && message.header.upv.minor === 1 && foundVersion === false) {
                foundVersion = true;
            } else if (message.header.upv.major === 1 && message.header.upv.minor === 1 && foundVersion === true) {
                throw new Error('Found two messages with the same version number!')
            }
        }

        if(!foundVersion)
            throw new Error('No messages for UAF v1.1 been returned!')
    })
})