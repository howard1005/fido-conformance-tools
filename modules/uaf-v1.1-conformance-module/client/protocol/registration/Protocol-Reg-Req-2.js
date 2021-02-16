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

        Protocol-Reg-Req-2

        Test the Registration Request Dictionary

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

    it(`F-1

        Send RegistrationRequest UAF message for the given metadata statement, with "header" field set to type of NOT a DICTIONARY, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].header = [];
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

        Send three RegistrationRequest UAF messages for the given metadata statement, with "header" field set to "null", "undefined" and "empty" DICTIONARY correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

    `, () => {
        it('header is undefined', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header = undefined;
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
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header = null;
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
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].header = {};
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

        Send RegistrationRequest UAF message for the given metadata statement, with "challenge" field set to type of NOT a DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].challenge = 0xdeadbeef;
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

        Send three RegistrationRequest UAF messages for the given metadata statement, with "challenge" field set to "null", "undefined" and "empty" DOMString correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

    `, () => {
        it('challenge is undefined', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].challenge = undefined;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('challenge is null', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].challenge = null;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('challenge is empty DICTIONARY', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].challenge = {};
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

    it(`F-5

        Send RegistrationRequest UAF message for the given metadata statement, with "username" field set to type of NOT a DOMString, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].username = 0xdeadbeef;
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    describe(`F-6

        Send three RegistrationRequest UAF messages for the given metadata statement, with "username" field set to "null", "undefined" and "empty" DOMString correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error

    `, () => {
        it('username is undefined', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].username = undefined;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('username is null', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].username = null;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('username is empty DICTIONARY', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].username = {};
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

    it(`F-7

        Send RegistrationRequest UAF message for the given metadata statement, with "policy" field set to type of NOT a DICTIONARY, wait for the response, and check that API response returns PROTOCOL_ERROR(0x06) error   

    `, () => {
        return getTestStaticJSON(`Protocol-Reg-Req-P`)
            .then((data) => {
                data[0].policy = '{}';
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    describe(`F-8

        Send three RegistrationRequest UAF messages for the given metadata statement, with "policy" field set to "null", "undefined" and "empty" DICTIONARY correspondingly, wait for the responses, and check that each API response returns a PROTOCOL_ERROR(0x06) error  

    `, () => {
        it('policy is undefined', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].policy = undefined;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('policy is null', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].policy = null;
                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('policy is empty DICTIONARY', () => {
            return getTestStaticJSON(`Protocol-Reg-Req-P`)
                .then((data) => {
                    data[0].policy = {};
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
