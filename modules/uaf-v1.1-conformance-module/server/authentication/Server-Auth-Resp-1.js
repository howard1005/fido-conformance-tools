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

        Server-Auth-Resp-1

        Test the Authentication Response SEQUENCE

    `, function() {

    let username = generateRandomString();
    let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
    before(() => {
        
        return rest.register.get(1200, username)
            .then((response) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => rest.register.post(data.uafProtocolMessage, 1200, username))
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Get authentication request, and generate valid authentication response, and send it to the server. Server must accept response. 

    `, () => {
        return rest.authenticate.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                return rest.authenticate.post(data.uafProtocolMessage, 1200, username)
            })
    })

/* ---------- Negative Tests ---------- */
    it(`F-1

        Get authentication request, and generate two valid authentication responses, with the same protocol version, and send it to the server. Server must reject response.    

    `, () => {
        return rest.authenticate.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let messages = tryDecodeJSON(data.uafProtocolMessage);
                messages.push(messages[0]);

                let uafResponse = JSON.stringify(messages)

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })
})
