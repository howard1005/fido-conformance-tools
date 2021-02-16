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

        Protocol-Auth-Req-6

        Test Client Processing Policy Rules

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
    

    before(function() {
        this.timeout(30000);
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((response) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(response),
                }

                return authenticator.processUAFOperation(uafmessage)
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })
/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push([{'aaid': [config.test.metadataStatement.aaid]}]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
    })

    it(`P-2

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
    })

/* ----- NEGATIVE TESTS ----- */
    describe(`F-1

        Send three AuthenticationRequest UAF messages for the given metadata statement, with "policy.accepted" field key set to "undefined", "null" and "empty" SEQUENCE correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

    `, () => {
        it('Policy.accepted is undefined', () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    data[0].policy.accepted = undefined;
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('Policy.accepted is null', () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    data[0].policy.accepted = null;
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('Policy.accepted is empty SEQUENCE', () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    data[0].policy.accepted = [];
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })
    })

    it(`F-2

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted = {};
                
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-3

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" SEQUENCE contains MatchCriteria items that are NOT stored in two-dimensional([][]) SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push({'aaid': [config.test.metadataStatement.aaid]})

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-4

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" SEQUENCE contains member that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push(28688)

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-5

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains member that is NOT of type DICTIONARY, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push([45232])

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-6

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.aaid" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push([{'aaid': config.test.metadataStatement.aaid}]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-7

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.aaid" SEQUENCE containing member that is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push([{'aaid': [config.test.metadataStatement.aaid, 42]}]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-8

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.vendorID" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push([{'aaid': [config.test.metadataStatement.aaid, 42]}]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-9

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.vendorID" SEQUENCE containing member that is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push([{
                    'vendorID': 32,
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-10

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.keyIDs" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push([{
                    'keyIDs': {},
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })


    it(`F-11

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.keyIDs" SEQUENCE containing member that is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {

                data[0].policy.accepted.push([{
                    'keyIDs': [0xdeadbeef],
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-12

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.keyIDs" SEQUENCE containing keyID that is NOT base64url encoded, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'keyIDs': ['mNxQs+Agq9GexsFq7t4VX/QR-sPYJKSZ2zdiUcJCab='],
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-13

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.userVerification" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'userVerification': '1023',
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-14

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.keyProtection" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'keyProtection': '10',
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-15

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.matcherProtection" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'matcherProtection': '4',
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-16

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.attachmentHint" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'matcherProtection': '2',
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-17

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.tcDisplay" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'matcherProtection': '0',
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-18

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.authenticationAlgorithms" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'authenticationAlgorithms': {},
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-19

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.authenticationAlgorithms" SEQUENCE containing member that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm, '4'],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-20

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.assertionSchemes" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': {}
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })


    it(`F-21

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.assertionSchemes" SEQUENCE containing member that is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme, 0xdeadbeef]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-22

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.attestationTypes" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme],
                    'attestationTypes': {}
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-23

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.attestationTypes" SEQUENCE containing member that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme],
                    'attestationTypes': [config.test.metadataStatement.attestationType, '15880']
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-24

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.authenticatorVersion" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'aaid': [config.test.metadataStatement.aaid],
                    'authenticatorVersion': '42'
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-25

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.exts" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'aaid': [config.test.metadataStatement.aaid],
                    'exts': {}
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-26

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria.exts" SEQUENCE containing member that is NOT of type DICTIONARY, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error         

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'aaid': [config.test.metadataStatement.aaid],
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': '',
                            'fail_if_unknown': false
                        },
                        []
                    ]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    describe(`F-27

        Run Protocol-Req-Req-5 Extension tests on MatchCriteria in "Policy.accepted" 

    `, () => {
        /* ----- POSITIVE TESTS ----- */
        it(`P-1

            Send a valid AuthenticationRequest, with, exts SEQUENCE containing one valid Extension object, with id of "unknown-id", data, and fail_if_unknown to be false, wait for the response, and check that API does NOT return an error 

        `, () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 'unknown-id',
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]

                    data[0].policy.accepted.push([{ 
                        'aaid': [config.test.metadataStatement.aaid],
                        'exts': extensions
                    }])
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationSucceed(uafmessage);
                })
        })

        /* ----- NEGATIVE TESTS ----- */
        it(`F-2

            Send AuthenticationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

        `, () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 0xdeadbeef,
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]

                    data[0].policy.accepted.push([{ 
                        'aaid': [config.test.metadataStatement.aaid],
                        'exts': extensions
                    }])
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it(`F-3

            Send AuthenticationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key length is larger than 32 characters, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

        `, () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 'some.companys.very.long.id.that.is.keep.going',
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]

                    data[0].policy.accepted.push([{ 
                        'aaid': [config.test.metadataStatement.aaid],
                        'exts': extensions
                    }])
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it(`F-4

            Send AuthenticationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "data" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error    

        `, () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 'unknown-id',
                            'data': 0xdeadbeef,
                            'fail_if_unknown': false
                        }
                    ]

                    data[0].policy.accepted.push([{ 
                        'aaid': [config.test.metadataStatement.aaid],
                        'exts': extensions
                    }])
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it(`F-5

            Send AuthenticationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key is NOT of type BOOLEAN, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

        `, () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 'unknown-id',
                            'data': 0xdeadbeef,
                            'fail_if_unknown': 'false'
                        }
                    ]

                    data[0].policy.accepted.push([{ 
                        'aaid': [config.test.metadataStatement.aaid],
                        'exts': extensions
                    }]);
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        describe(`F-6

            Send three AuthenticationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "id" key set to "undefined", "null" and "empty" DOMString correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

        `, () => {
            it('Extension.id is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {
                                'data': '',
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.accepted.push([{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }])
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
            it('Extension.id is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {   
                                'id': null,
                                'data': '',
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.accepted.push([{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }])
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('Extension.id is empty DOMString', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {
                                'id': '',
                                'data': '',
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.accepted.push([{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }])
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        })

        it(`F-7

            Send two AuthenticationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "data" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

        `, () => {
            it('Extension.data is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {
                                'id': 'unknown-id',
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.accepted.push([{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }])
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
            it('Extension.data is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {   
                                'id': 'unknown-id',
                                'data': null,
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.accepted.push([{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }])
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        })

        it(`F-8

            Send two AuthenticationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

        `, () => {
            it('Extension.fail_if_unknown is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {
                                'id': 'unknown-id',
                                'data': ''
                            }
                        ]

                        data[0].policy.accepted.push([{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }])
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
            it('Extension.fail_if_unknown is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {   
                                'id': 'unknown-id',
                                'data': '',
                                'fail_if_unknown': null
                            }
                        ]

                        data[0].policy.accepted.push([{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }])
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        })
    })

    it(`F-28

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria" that has "aaid" field, that is combined with a key other than "keyIDs", "attachmentHint", "authenticatorVersion", and "exts", wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'aaid': [config.test.metadataStatement.aaid],
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-29

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria" that missing "aaid" field, and "authenticationAlgorithms" field is missing as well, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'assertionSchemes': [config.test.metadataStatement.assertionScheme]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-30

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.accepted" two-dimensional([][]) SEQUENCE contains "MatchCriteria" that missing "aaid" field, and "assertionSchemes" field is missing as well, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.accepted.push([{
                    'authenticationAlgorithms': [config.test.metadataStatement.authenticationAlgorithm]
                }]);

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-31

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = {};

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-32

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains member that is NOT of type DICTIONARY, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{'aaid': ['FFFF#FFFF']}, 0xdeadbeef]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-33

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.aaid" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{'aaid': 'FFFF#FFFF'}]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-34

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.aaid" SEQUENCE containing member that is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{'aaid': ['FFFF#FFFF', {}]}]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-35

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.vendorID" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05, 0x06],
                    'assertionSchemes': ['UAFV1TLV'],
                    'vendorID': '1234'
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-36

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.vendorID" SEQUENCE containing member that is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05, 0x06],
                    'assertionSchemes': ['UAFV1TLV'],
                    'vendorID': ['1234', 0xFFFF]
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-37

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.keyIDs" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'aaid': ['FFFF#FFFF'],
                    'keyIDs': {}
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-38

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.keyIDs" SEQUENCE containing member that is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'aaid': ['FFFF#FFFF'],
                    'keyIDs': ['K24wCrZG6g8v0Fy7crKhpeRd8SmY9olPV2sl8-LK', {}]
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-39

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.keyIDs" SEQUENCE containing keyID that is NOT base64url encoded, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'aaid': ['FFFF#FFFF'],
                    'keyIDs': ['vpDve+LIRWNQyiKoh/Zwe0bFscMmVh4YsqW/3T19+LK']
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-40

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.userVerification" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05, 0x06],
                    'assertionSchemes': ['UAFV1TLV'],
                    'userVerification': '1023'
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })


    it(`F-41

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.keyProtection" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05, 0x06],
                    'assertionSchemes': ['UAFV1TLV'],
                    'keyProtection': '4'
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-42

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.matcherProtection" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05, 0x06],
                    'assertionSchemes': ['UAFV1TLV'],
                    'matcherProtection': '4'
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-43

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.attachmentHint" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05, 0x06],
                    'assertionSchemes': ['UAFV1TLV'],
                    'attachmentHint': '1'
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-44

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.tcDisplay" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05, 0x06],
                    'assertionSchemes': ['UAFV1TLV'],
                    'tcDisplay': '0'
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-45

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.authenticationAlgorithms" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': {},
                    'assertionSchemes': ['UAFV1TLV']
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-46

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.authenticationAlgorithms" SEQUENCE containing member that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05, '0x06'],
                    'assertionSchemes': ['UAFV1TLV']
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-47

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.assertionSchemes" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05, '0x06'],
                    'assertionSchemes': {}
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-48

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.assertionSchemes" SEQUENCE containing member that is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05],
                    'assertionSchemes': ['UAFV1TLV', {}]
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-49

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.attestationTypes" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05],
                    'assertionSchemes': ['UAFV1TLV'],
                    'attestationTypes': '15880'
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })


    it(`F-50

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.attestationTypes" SEQUENCE containing member that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05],
                    'assertionSchemes': ['UAFV1TLV'],
                    'attestationTypes': [15879, '15880']
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })


    it(`F-51

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.authenticatorVersion" that is NOT of type NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'aaid': ['FFFF#FFFF'],
                    'authenticatorVersion': '4'
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-52

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.exts" that is NOT of type SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'aaid': ['FFFF#FFFF'],
                    'exts': {}
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-53

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria.exts" SEQUENCE containing member that is NOT of type DICTIONARY, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'aaid': ['FFFF#FFFF'],
                    'exts': [
                        {
                            'id': 'unknown-id',
                            'data': '',
                            'fail_if_unknown': false
                        },
                        []
                    ]
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    describe(`F-54

        Run Protocol-Req-Req-5 Extension test on MatchCriteria in "Policy.disallowed"

    `, () => {
        /* ----- NEGATIVE TESTS ----- */
        it(`F-2

            Send AuthenticationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

        `, () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 0xdeadbeef,
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]

                    data[0].policy.disallowed = [{ 
                        'aaid': [config.test.metadataStatement.aaid],
                        'exts': extensions
                    }]
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it(`F-3

            Send AuthenticationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key length is larger than 32 characters, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

        `, () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 'some.companys.very.long.id.that.is.keep.going',
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]

                    data[0].policy.disallowed = [{ 
                        'aaid': [config.test.metadataStatement.aaid],
                        'exts': extensions
                    }]
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it(`F-4

            Send AuthenticationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "data" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error    

        `, () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 'unknown-id',
                            'data': 0xdeadbeef,
                            'fail_if_unknown': false
                        }
                    ]

                    data[0].policy.disallowed = [{ 
                        'aaid': [config.test.metadataStatement.aaid],
                        'exts': extensions
                    }]
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it(`F-5

            Send AuthenticationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key is NOT of type BOOLEAN, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

        `, () => {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 'unknown-id',
                            'data': 0xdeadbeef,
                            'fail_if_unknown': 'false'
                        }
                    ]

                    data[0].policy.disallowed = [{ 
                        'aaid': [config.test.metadataStatement.aaid],
                        'exts': extensions
                    }];
                    
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        describe(`F-6

            Send three AuthenticationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "id" key set to "undefined", "null" and "empty" DOMString correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

        `, () => {
            it('Extension.id is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {
                                'data': '',
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.disallowed = [{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }]
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
            it('Extension.id is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {   
                                'id': null,
                                'data': '',
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.disallowed = [{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }]
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('Extension.id is empty DOMString', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {
                                'id': '',
                                'data': '',
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.disallowed = [{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }]
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        })

        it(`F-7

            Send two AuthenticationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "data" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

        `, () => {
            it('Extension.data is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {
                                'id': 'unknown-id',
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.disallowed = [{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }]
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
            it('Extension.data is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {   
                                'id': 'unknown-id',
                                'data': null,
                                'fail_if_unknown': false
                            }
                        ]

                        data[0].policy.disallowed = [{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }]
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        })

        it(`F-8

            Send two AuthenticationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

        `, () => {
            it('Extension.fail_if_unknown is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {
                                'id': 'unknown-id',
                                'data': ''
                            }
                        ]

                        data[0].policy.disallowed = [{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }]
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
            it('Extension.fail_if_unknown is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {
                        let extensions = [
                            {   
                                'id': 'unknown-id',
                                'data': '',
                                'fail_if_unknown': null
                            }
                        ]

                        data[0].policy.disallowed = [{ 
                            'aaid': [config.test.metadataStatement.aaid],
                            'exts': extensions
                        }]
                        
                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        })
    })

    it(`F-55

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria" that has "aaid" field, that is combined with a key other than "keyIDs", "attachmentHint", "authenticatorVersion", and "exts", wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'aaid': ['FFFF#FFFF'],
                    'assertionSchemes': ['UAFV1TLV']
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-56

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria" that missing "aaid" field, and "authenticationAlgorithms" field is missing as well, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'assertionSchemes': ['UAFV1TLV']
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-57

        Send AuthenticationRequest UAF message for the given metadata statement, with "policy.disallowed" SEQUENCE contains "MatchCriteria" that missing "aaid" field, and "assertionSchemes" field is missing as well, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Auth-Req-P')
            .then((data) => {
                data[0].policy.disallowed = [{
                    'authenticationAlgorithms': [0x01, 0x02, 0x05]
                }]

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(0x06, errorCode, `Expected client to return PROTOCOL_ERROR(0x06), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })
})
