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

        Server-Auth-Req-2

        Test the AuthenticationRequest DICTIONARY

    `, function() {

    let authenticationRequest;
    let username = generateRandomString();
    before(() => {
        return rest.register.get(1200, username)
            .then((response) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((data) => {
                authenticationRequest = data[0];
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Message MUST contain "header" field, of type Dictionary 

    `, () => {
        assert.isObject(authenticationRequest.header, 'OperationHeader MUST be of type DICTIONARY')
    })

    it(`P-2

        Message MUST contain "challenge" field, of type DOMString, and: 
            (a) MUST not be empty 
            (b) Length of the challenge MUST NOT be less than 11 characters(8 bytes base64url encoded) long
            (c) Length of the challenge MUST NOT be more than 85 characters(64 bytes base64url encoded) 
            (d) Challenge MUST be base64url without padding encoded
            (e) Perform two consecutive requests to the target server, wait for the responses and check that authenticationRequestA.challenge does NOT equal authenticationRequestB.challenge.

    `, () => {
        assert.isString(authenticationRequest.challenge, 'Challenge MUST be of type DOMString!');
        assert.isNotEmpty(authenticationRequest.challenge, 'Challenge can not be empty!');
        assert.isAtLeast(authenticationRequest.challenge.length, 11, 'Challenge MUST be at least 8 bytes(11 base64url characters) long!');
        assert.isAtMost(authenticationRequest.challenge.length, 86, 'Challenge can be max of 64 bytes(86 base64url characters) long!');
        assert.match(authenticationRequest.challenge, /^[a-zA-Z0-9_-]+$/, 'Challenge MUST be base64URL(without padding) encoded!');

        let requestA = rest.authenticate.get(1200, username)
            .then((data) => {
               return data[0].challenge
            })

        let requestB = rest.authenticate.get(1200, username)
            .then((data) => {
               return data[0].challenge
            })

        return Promise.all([requestA, requestB])
            .then((result) => {
                assert.notStrictEqual(result[0], result[1], `Server returned two identical challeges for request A(${result[0]}) and B(${result[1]}). Server MUST generate unique challenge for each of the AuthenticationRequest!`);
            })
    })

    it(`P-3

        Get AuthenticationRequest with transaction confirmation request, for authenticator that supports transaction of type "text/plain". Check "transaction" field is of type SEQUENCE, and for each member, check that: 
            (a) "Transaction.contentType" must be set to "text/plain" 
            (b) "Transaction.content" must be of type DOMString and must not be empty 
            (c) "Transaction.content" must be base64url encoded 
            (d) "Transaction.content" must decode to UTF-8 that is max of 200 characters

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
        let transactionString = 'Transfer 200$ to Bob\'s account?';

        return rest.register.get(1200, username)
            .then((response) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, transactionString))
            .then((data) => {
                let authenticationRequest = data[0];
                assert.isArray(authenticationRequest.transaction, 'transaction field MUST be of type SEQUENCE!');

                let transaction = authenticationRequest.transaction[0];

                assert.strictEqual(transaction.contentType, 'text/plain', 'Transaction.contentType MUST be set to "text/plain"!');
                assert.isString(transaction.content, 'Transaction.content MUST be of type DOMString!')
                assert.isNotEmpty(transaction.content, 'Transaction.content MUST NOT be empty!')
                assert.match(transaction.content, /^[a-zA-Z0-9_-]+$/, 'Transaction.content MUST be base64URL(without padding) encoded!');

                let transactionB64String = stringToBase64URL(transactionString);

                assert.strictEqual(transaction.content, transactionB64String, `For text/plain authenticator, Transaction.content MUST be the base64url encoding of the text transaction! \n Expected ${transaction.content} to equal ${contentString}!`);
            })
    })

    it(`P-4

        Get AuthenticationRequest with transaction confirmation request, for authenticator that supports transaction of type "image/png". Check "transaction" field is of type SEQUENCE, and for each member, check that: 
            (a) "Transaction.contentType" must be set to "image/png" 
            (b) "Transaction.content" must be of type DOMString and must not be empty 
            (c) "Transaction.content" must be base64url encoded 
            (d) "Transaction.content" must be a valid URL encoded PNG image

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC02')

        return rest.register.get(1200, username)
            .then((response) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Bob\'s account?'))
            .then((data) => {
                let authenticationRequest = data[0];
                assert.isArray(authenticationRequest.transaction, 'transaction field MUST be of type SEQUENCE!');

                let transaction = authenticationRequest.transaction[0];

                assert.strictEqual(transaction.contentType, 'image/png', 'Transaction.contentType MUST be set to "image/png"!');
                assert.isString(transaction.content, 'Transaction.content MUST be of type DOMString!')
                assert.isNotEmpty(transaction.content, 'Transaction.content MUST NOT be empty!')
                assert.match(transaction.content, /^[a-zA-Z0-9_-]+$/, 'Transaction.content MUST be base64URL(without padding) encoded!');
            })
    })

    it(`P-5

        Message MUST contain "policy" field, of type Dictionary 

    `, () => {
        assert.isObject(authenticationRequest.policy, 'Policy MUST be of type DICTIONARY')
    })
})