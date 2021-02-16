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

        Protocol-Auth-Resp-1

        Test the Authentication Response Message SEQUENCE

    `, function() {

    this.timeout(30000);
    this.retries(3);

    after(() => {
       return getTestStaticJSON(`Protocol-Dereg-Req-P`)
        .then((data) => {
            data[0].authenticators = [{'aaid': '', 'keyID': ''}]
            
            let uafmessage = {'uafProtocolMessage' : JSON.stringify(data)}

            return expectProcessUAFOperationSucceed(uafmessage);
        })
    })
    

    let authenticationAssertions = undefined;
    before(function() {
        this.timeout(30000);
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((data) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data)
                }
                return authenticator.processUAFOperation(uafmessage)
            })
            .then((data) => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
            })
            .then((data) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data)
                }

                return authenticator.processUAFOperation(uafmessage)
            })
            .then((data) => {
                authenticationAssertions = tryDecodeJSON(data.uafProtocolMessage);
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    });

/* ---------- Positive Tests ---------- */
    it(`P-1

        Check that AuthenticationResponse SEQUENCE does NOT contain two responses with the same protocol version.

    `, () => {
        let foundVersion = false;

        for (let message of authenticationAssertions) {
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
