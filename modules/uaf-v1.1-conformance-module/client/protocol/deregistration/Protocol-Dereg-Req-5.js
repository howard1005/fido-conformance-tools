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

        Protocol-Dereg-Req-5

        Test the Extension array

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

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid DeregistrationRequest, with, exts SEQUENCE containing one valid Extension object, with id of "unknown-id", data, and fail_if_unknown to be false, wait for the response, and check that API does NOT return an error 

    `, () => {
        return getTestStaticJSON('Protocol-Dereg-Req-P')
            .then((data) => {
                let extensions = [
                    {
                        'id': 'unknown-id',
                        'data': '',
                        'fail_if_unknown': false
                    }
                ]
                data[0].header.exts    = extensions;
                data[0].authenticators = deregistrationAuthenticators;
                
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
    })

/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send a valid DeregistrationRequest, with, exts SEQUENCE containing one valid Extension object, with id of "unknown-id", data, and fail_if_unknown to be true, wait for the response, and check that API response returns UNKNOWN(0xFF) error

    `, () => {
        return getTestStaticJSON('Protocol-Dereg-Req-P')
            .then((data) => {
                let extensions = [
                    {
                        'id': 'unknown-id',
                        'data': '',
                        'fail_if_unknown': true
                    }
                ]
                data[0].header.exts    = extensions;
                data[0].authenticators = deregistrationAuthenticators;
                
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.strictEqual(INTERFACE_STATUS_CODES_TO_INT.UNKNOWN, errorCode, `Expected client to return UNKNOWN(0xFF), got ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-2

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Dereg-Req-P')
            .then((data) => {
                let extensions = [
                    {
                        'id': 0xdeadbeef,
                        'data': '',
                        'fail_if_unknown': false
                    }
                ]
                data[0].header.exts    = extensions;
                data[0].authenticators = deregistrationAuthenticators;
                
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

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "id" key length is larger than 32 characters, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON('Protocol-Dereg-Req-P')
            .then((data) => {
                let extensions = [
                    {
                        'id': 'some.companys.very.long.id.that.is.keep.going',
                        'data': '',
                        'fail_if_unknown': false
                    }
                ]
                data[0].header.exts    = extensions;
                data[0].authenticators = deregistrationAuthenticators;
                
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

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "data" key is NOT of type DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error    

    `, () => {
        return getTestStaticJSON('Protocol-Dereg-Req-P')
            .then((data) => {
                let extensions = [
                    {
                        'id': 'unknown-id',
                        'data': 0xdeadbeef,
                        'fail_if_unknown': false
                    }
                ]
                data[0].header.exts    = extensions;
                data[0].authenticators = deregistrationAuthenticators;
                
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

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key is NOT of type BOOLEAN, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

    `, () => {
        return getTestStaticJSON('Protocol-Dereg-Req-P')
            .then((data) => {
                let extensions = [
                    {
                        'id': 'unknown-id',
                        'data': 0xdeadbeef,
                        'fail_if_unknown': 'false'
                    }
                ]
                data[0].header.exts    = extensions;
                data[0].authenticators = deregistrationAuthenticators;
                
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

        Send three DeregistrationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "id" key set to "undefined", "null" and "empty" DOMString correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

    `, () => {
        it('Extension.id is undefined', () => {
            return getTestStaticJSON('Protocol-Dereg-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]
                    data[0].header.exts    = extensions;
                    data[0].authenticators = deregistrationAuthenticators;
                    
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
            return getTestStaticJSON('Protocol-Dereg-Req-P')
                .then((data) => {
                    let extensions = [
                        {   
                            'id': null,
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]
                    data[0].header.exts    = extensions;
                    data[0].authenticators = deregistrationAuthenticators;
                    
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
            return getTestStaticJSON('Protocol-Dereg-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': '',
                            'data': '',
                            'fail_if_unknown': false
                        }
                    ]
                    data[0].header.exts    = extensions;
                    data[0].authenticators = deregistrationAuthenticators;
                    
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

        Send two DeregistrationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "data" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

    `, () => {
        it('Extension.data is undefined', () => {
            return getTestStaticJSON('Protocol-Dereg-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 'unknown-id',
                            'fail_if_unknown': false
                        }
                    ]
                    data[0].header.exts    = extensions;
                    data[0].authenticators = deregistrationAuthenticators;
                    
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
            return getTestStaticJSON('Protocol-Dereg-Req-P')
                .then((data) => {
                    let extensions = [
                        {   
                            'id': 'unknown-id',
                            'data': null,
                            'fail_if_unknown': false
                        }
                    ]
                    data[0].header.exts    = extensions;
                    data[0].authenticators = deregistrationAuthenticators;
                    
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

        Send two DeregistrationRequest UAF messages for the given metadata statement, with "header.exts" field containing Extension with "fail_if_unknown" key set to "undefined" and "null" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

    `, () => {
        it('Extension.fail_if_unknown is undefined', () => {
            return getTestStaticJSON('Protocol-Dereg-Req-P')
                .then((data) => {
                    let extensions = [
                        {
                            'id': 'unknown-id',
                            'data': ''
                        }
                    ]
                    data[0].header.exts    = extensions;
                    data[0].authenticators = deregistrationAuthenticators;
                    
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
            return getTestStaticJSON('Protocol-Dereg-Req-P')
                .then((data) => {
                    let extensions = [
                        {   
                            'id': 'unknown-id',
                            'data': '',
                            'fail_if_unknown': null
                        }
                    ]
                    data[0].header.exts    = extensions;
                    data[0].authenticators = deregistrationAuthenticators;
                    
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
