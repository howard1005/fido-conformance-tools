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

        Server-Reg-Req-2

        Test the RegistrationRequest dictionary

    `, function() {

    let registrationRequest = undefined;
    before(() => {
        return rest.register.get(1200)
            .then((data) => {
               registrationRequest = data[0];
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    });

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Message MUST contain "header" field, of type Dictionary 

    `, () => {
        assert.isObject(registrationRequest.header, 'OperationHeader MUST be of type DICTIONARY')
    })

    it(`P-2

        Message MUST contain "challenge" field, of type DOMString, and: 
            (a) MUST not be empty 
            (b) Length of the challenge MUST NOT be less than 11 characters(8 bytes base64url encoded) long
            (c) Length of the challenge MUST NOT be more than 85 characters(64 bytes base64url encoded) 
            (d) Challenge MUST be base64url without padding encoded
            (e) Perform two consecutive requests to the target server, wait for the responses and check that RegistrationRequestA.challenge does NOT equal RegistrationRequestB.challenge.

    `, () => {
        assert.isString(registrationRequest.challenge, 'Challenge MUST be of type DOMString!');
        assert.isNotEmpty(registrationRequest.challenge, 'Challenge can not be empty!');
        assert.isAtLeast(registrationRequest.challenge.length, 11, 'Challenge MUST be at least 8 bytes(11 base64url characters) long!');
        assert.isAtMost(registrationRequest.challenge.length, 86, 'Challenge can be max of 64 bytes(86 base64url characters) long!');
        assert.match(registrationRequest.challenge, /^[a-zA-Z0-9_-]+$/, 'Challenge MUST be base64URL(without padding) encoded!');

        let requestA = rest.register.get(1200)
            .then((data) => {
               return data[0].challenge
            })

        let requestB = rest.register.get(1200)
            .then((data) => {
               return data[0].challenge
            })

        return Promise.all([requestA, requestB])
            .then((result) => {
                assert.notStrictEqual(result[0], result[1], `Server returned two identical challeges for request A(${result[0]}) and B(${result[1]}). Server MUST generate unique challenge for each of the RegistrationRequest!`);
            })
    })

    it(`P-3

        Message MUST contain "username" field, of type DOMString, and: 
            (a) MUST not be empty. 
            (b) Length of the username MUST be at least 1 character.
            (c) Length of the username MUST not be more than 128 characters.

    `, () => {
        assert.isString(registrationRequest.username, 'Username MUST be of type DOMString!');
        assert.isNotEmpty(registrationRequest.username, 'Username can not be empty!');
        assert.isAtLeast(registrationRequest.username.length, 1, 'Username MUST be at least 1 character long!');
        assert.isAtMost(registrationRequest.username.length, 128, 'Username can be max of 128 characters long!');
    })

    it(`P-4

        Message MUST contain "policy" field, of type Dictionary 

    `, () => {
        assert.isObject(registrationRequest.policy, 'Policy MUST be of type DICTIONARY')
    })
})