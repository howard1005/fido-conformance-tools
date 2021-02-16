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

        Protocol-Reg-Req-3

        Test OperationHeader in the Registration Request Dictionary

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

    describe(`F-1

        Send three RegistrationRequest UAF messages for the given metadata statement, with "header.upv" field set to "undefined", "null" and "empty" DICTIONARY correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

    `, () => {
        it('UPV is undefined', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.upv = undefined;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('UPV is null', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.upv = null;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('UPV is empty DICTIONARY', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.upv = {};
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

        Send RegistrationRequest UAF message for the given metadata statement, with "header.upv" field set to type of NOT a DICTIONARY, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.upv = '{}';
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

        Send two RegistrationRequest UAF messages for the given metadata statement, with "header.upv.major" field set to "null" and "undefined" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

    `, () => {
        it('UPV.major is undefined', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.upv.major = undefined;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('UPV.major is null', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.upv.major = null;
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
    
        Send RegistrationRequest UAF message for the given metadata statement, with "header.upv.major" field set to type of NOT a NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.upv.major = '1';
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

        Send two RegistrationRequest UAF messages for the given metadata statement, with "header.upv.minor" field set to "null" and "undefined" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

    `, () => {
        it('UPV.minor is undefined', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.upv.minor = undefined;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('UPV.minor is null', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.upv.minor = null;
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

        Send RegistrationRequest UAF message for the given metadata statement, with "header.upv.minor" field set to type of NOT a NUMBER, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.upv.minor = '1';
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
        
        Send RegistrationRequest UAF message for the given metadata statement, with "header.upv" field set the unsupported protocol version({"major": 1, "minor": 7}), wait for the response, and check that API response returns UNSUPPORTED_VERSION(0x04).

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.upv = {"major": 1, "minor": 7};
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x04, `Expected UNSUPPORTED_VERSION(0x04) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })


    describe(`F-8

        Send three RegistrationRequest UAF messages for the given metadata statement, with "header.op" field set to "null", "undefined" and "empty" DOMString correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error    

    `, () => {
        it('op is undefined', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.op = undefined;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('op is null', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.op = null;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('op is empty DOMString', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.op = '';
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

        Send RegistrationRequest UAF message for the given metadata statement, with "header.op" field set to type of NOT a DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.op = 0xdeadbeef;
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

        Send two RegistrationRequest UAF messages for the given metadata statement, with "header.op" field set to "REG" and "reg" correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error    

    `, () => {
        it('op is REG', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.op = 'REG';
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('op is reg', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header.op = 'reg';
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
        
        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" field set to type of NOT a DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.appID = 0xdeadbeef;
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
        
        Send RegistrationRequest UAF message for the given metadata statement, with "header.serverData" field set to type of NOT a DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.serverData = 0xdeadbeef;
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

        Send RegistrationRequest UAF message for the given metadata statement, with "header.serverData" field length larger than 1536 characters, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.serverData = generateRandomString(2000);
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
        
        Send RegistrationRequest UAF message for the given metadata statement, with "header.serverData" field length set to zero(0), wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.serverData = '';
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
        
        Send RegistrationRequest UAF message for the given metadata statement, with "header.exts" field set to type of NOT a SEQUENCE, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header.exts = {};
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
