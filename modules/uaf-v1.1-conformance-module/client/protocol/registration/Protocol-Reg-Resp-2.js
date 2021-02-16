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

        Protocol-Reg-Resp-2

        Test the Registration Response Dictionary

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

    let registrationRequest = undefined;
    let registrationAssertion = undefined;
    before(function() {
        this.timeout(30000);
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((data) => {
                registrationRequest = data[0];
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }
                return authenticator.processUAFOperation(uafmessage)
            })
            .then((response) => {
                registrationAssertion = tryDecodeJSON(response.uafProtocolMessage)[0];
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    });

/* ---------- Positive Tests ---------- */
    it(`P-1

        Check that RegistrationResponse "header" field is of type DICTIONARY and STRICTLY EQUAL to the "RegistrationRequest.header" 

    `, () => {
        assert.deepEqual(registrationAssertion.header, registrationRequest.header, `Expected Request.header ${JSON.stringify(registrationRequest.header, null, 4)} to equal ${JSON.stringify(registrationAssertion.header, null, 4)}`)
    })

    it(`P-2

        Check that RegistrationResponse "fcParams" field is of type DOMString, is Base64URL encoded JSON DICTIONARY, and:
            (a) Check that FinalChallengeParams.appID MUST NOT be empty, and must be either taken from OperationHeader.appID, or if such empty MUST be set to facetID
            (b) Check that FinalChallengeParams.facetID is of type DOMString and is NOT empty 
            (c) Check that FinalChallengeParams.challenge is equal to header.challenge 
            (d) Check that FinalChallengeParams.channelBinding is of type DICTIONARY

    `, () => {
        let jsonString;
        try {
            jsonString = B64URLToUTF8(registrationAssertion.fcParams);
        } catch(e) {
            throw new Error(`Error while decoding Base64URL encoded fcParams. Error message is: \n${e}`);
        }

        let fcParams;
        try {
            fcParams = tryDecodeJSON(jsonString);
        } catch(e) {
            throw new Error(`Error while decoding JSON parsing fcParams. Error message is: \n${e}`);
        }

        if(registrationRequest.header.appID)
            assert.strictEqual(fcParams.appID, registrationRequest.header.appID, 'FinalChallengeParams.appID MUST be taken from Request.header.appID!');
        else
            assert.strictEqual(fcParams.appID, fcParams.facetID, 'If OperationHeader.appID is empty, null or undefined, FinalChallengeParams.appID MUST be set to facetID!');

        assert.isString(fcParams.facetID, 'FinalChallengeParams.facetID MUST be a string!');
        assert.isNotEmpty(fcParams.facetID, 'FinalChallengeParams.facetID MUST not be empty!');
        assert.strictEqual(fcParams.challenge, registrationRequest.challenge, 'FinalChallengeParams.challenge MUST strictly equal to registrationRequest.challenge!');
        assert.isObject(fcParams.channelBinding, 'FinalChallengeParams.channelBinding MUST be a DICTIONARY!');
    })

    it(`P-3

        Check that RegistrationResponse "assertions" field is of type SEQUENCE and contains at least one assertion

    `, () => {
        assert.isArray(registrationAssertion.assertions, 'Response.assertions MUST be SEQUENCE!');
        assert.isNotEmpty(registrationAssertion.assertions, 'Response.assertions MUST contain at least one assertion!')
    })
})
