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

        Protocol-Dereg-Req-3

        Test the Deregistration Request Header

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
    describe(`F-1

        Send three DeregistrationRequest UAF messages for the given metadata statement, with "header.upv" field set to "null", "undefined" and "empty" DICTIONARY correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error    

    `, () => {
        it('header.upv is undefined', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.upv = undefined;
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

        it('header.upv is null', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.upv = null;
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

        it('header.upv is an empty DICTIONARY', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.upv = {};
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

    it(`F-2

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.upv" field set to type of NOT a DICTIONARY, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.upv = '{}';
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

    describe(`F-3

        Send two DeregistrationRequest UAF messages for the given metadata statement, with "header.upv.major" field set to "null" and "undefined" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error    

    `, () => {
        it('header.upv.major is undefined', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.upv.major = undefined;
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

        it('header.upv.major is null', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.upv.major = null;
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

    it(`F-4

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.upv.major" field set to type of NOT a NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.upv.major = '1';
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

    describe(`F-5

        Send two DeregistrationRequest UAF messages for the given metadata statement, with "header.upv.minor" field set to "null" and "undefined" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error    

    `, () => {
        it('header.upv.minor is undefined', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.upv.minor = undefined;
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

        it('header.upv.minor is null', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.upv.minor = null;
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

    it(`F-6

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.upv.minor" field set to type of NOT a NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.upv.minor = '1';
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

    it(`F-7

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.upv" field set the unsupported protocol version({"major": 1, "minor": 7}), wait for the response, and check that API response returns UNSUPPORTED_VERSION(0x04).  

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.upv = {"major": 1, "minor": 7};
                data[0].authenticators = deregistrationAuthenticators;
                
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x04, `UNSUPPORTED_VERSION(0x04) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    describe(`F-8

        Send three DeregistrationRequest UAF messages for the given metadata statement, with "header.op" field set to "null", "undefined" and "empty" DOMString correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

    `, () => {
        it('header.op is undefined', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.op = undefined;
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

        it('header.op is null', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.op = null;
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

        it('header.op is an empty DOMString', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.op = {};
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

    it(`F-9

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.op" field set to type of NOT a DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.op = 0xdead;
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

    describe(`F-10

        Send two DeregistrationRequest UAF messages for the given metadata statement, with "header.op" field set to "DEREG" and "dereg" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

    `, () => {
        it('header.op is "DEREG"', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.op = 'DEREG';
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

        it('header.op is "dereg"', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].header.op = 'dereg';
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

    it(`F-12

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.appID" field set to type of NOT a DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error    

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.appID = 0xdead;
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

    it(`F-13

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.serverData" field set to type of NOT a DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.serverData = 0xdead;
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

    it(`F-14

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.serverData" field length larger than 1536 characters, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.serverData = generateRandomString(2000);
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

    it(`F-15

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.serverData" field length set to zero(0), wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error    

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.serverData = '';
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

    it(`F-16

        Send DeregistrationRequest UAF message for the given metadata statement, with "header.exts" field set to type of NOT a SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].header.exts = {};
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
