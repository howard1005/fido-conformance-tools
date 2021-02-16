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

        Protocol-Dereg-Req-2

        Test the Deregistration Request Dictionary

    `, function() {
        
    this.timeout(30000);
    this.retries(3);

    let registrationAssertion        = undefined;
    let deregistrationAuthenticators = [];
    beforeEach(function() {
        this.timeout(30000);
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((response) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(response),
                }
                return authenticator.processUAFOperation(uafmessage)
            })
            .then((response) => {
                registrationAssertion = tryDecodeJSON(response.uafProtocolMessage);
                let tlv = new TLV({
                    'TagFieldSize' : 2,
                    'LengthFieldSize' : 2,
                    'TagDirectory': TAG_DIR,
                    'CustomTagParser': window.UAF.helpers.CustomTagParser
                })
                let TLVBUFFER = base64url.decode(registrationAssertion[0].assertions[0].assertion);
                let TLVSTRUCT = tlv.parser.parse(TLVBUFFER);
                let keyID = TLVSTRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_KEYID;

                deregistrationAuthenticators = [{
                    'aaid': window.config.test.metadataStatement.aaid,
                    'keyID': keyID
                }]
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

    after(() => {
       return getTestStaticJSON(`Protocol-Dereg-Req-P`)
        .then((data) => {
            data[0].authenticators = [{'aaid': '', 'keyID': ''}]
            
            let uafmessage = {'uafProtocolMessage' : JSON.stringify(data)}

            return expectProcessUAFOperationSucceed(uafmessage);
        })
    })


/* ---------- Negative Tests ---------- */
    it(`F-1

        Send DeregistrationRequest UAF message for the given metadata statement, with "header" field set to type of NOT a DICTIONARY, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header = '{}';
                data[0].authenticators = deregistrationAuthenticators;

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    describe(`F-2

        Send three DeregistrationRequest UAF messages for the given metadata statement, with "header" field set to "null", "undefined" and "empty" DICTIONARY correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error      

    `, () => {
        it('header is undefined', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header = undefined;
                    data[0].authenticators = deregistrationAuthenticators;

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('header is null', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header = null;
                    data[0].authenticators = deregistrationAuthenticators;

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('header is empty DICTIONARY', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header = {};
                    data[0].authenticators = deregistrationAuthenticators;

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })
    })

    it(`F-3

        Send DeregistrationRequest UAF message for the given metadata statement, with "authenticators" field set to type of NOT a SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].authenticators = '[]';

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    describe(`F-4

        Send three DeregistrationRequest UAF messages for the given metadata statement, with "authenticators" field set to "null", "undefined" and "empty" SEQUENCE correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

    `, () => {
        it('authenticators is undefined', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].authenticators = undefined;

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('authenticators is null', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].authenticators = null;

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('authenticators is empty SEQUENCE', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].authenticators = {};

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })
    })
})
