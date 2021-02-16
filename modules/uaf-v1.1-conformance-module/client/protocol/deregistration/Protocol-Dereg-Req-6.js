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

        Protocol-Dereg-Req-6

        Test the Client processing DeregisterAuthenticators

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

    it(`P-1

        Send DeregistrationRequest with "authenticator" SEQUENCE containing "DeregistrationRequest" with "keyID" field set to the unknown keyID, wait for the response, and check that request succeeds.

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].authenticators = [
                    {
                        'aaid': window.config.test.metadataStatement.aaid,
                        'keyID': generateRandomBase64urlBytes(32)
                    }
                ];

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
    })

    it(`P-2

        Register three usernames with the tested authenticator. Send a valid DeregistrationRequest with "authenticator" and "aaid" fields set to empty string, wait for the response, and check that request succeeds. Send a valid authentication request, wait for the response, and check that API returns a NO_SUITABLE_AUTHENTICATOR(0x05) error  

    `, () => {
        let regMessageTemplate;
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((data) => {
                regMessageTemplate = data;
                regMessageTemplate[0].username = generateRandomString(15);
                let uafmessage = {'uafProtocolMessage' : JSON.stringify(regMessageTemplate)}
                return expectProcessUAFOperationSucceed(uafmessage)
            })
            .then(() => {
                regMessageTemplate[0].username = generateRandomString(15);
                let uafmessage = {'uafProtocolMessage' : JSON.stringify(regMessageTemplate)}
                return expectProcessUAFOperationSucceed(uafmessage)
            })
            .then(() => {
                regMessageTemplate[0].username = generateRandomString(15);
                let uafmessage = {'uafProtocolMessage' : JSON.stringify(regMessageTemplate)}
                return expectProcessUAFOperationSucceed(uafmessage)
            })
            .then(() => {
                return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            })
            .then((data) => {
                data[0].authenticators = [
                    {
                        'aaid': '',
                        'keyID': ''
                    }
                ];
                
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
            .then(() => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
            })
            .then((data) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x05, `Expected NO_SUITABLE_AUTHENTICATOR(0x05) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
            })
    })

    it(`P-3

        Register three usernames with the tested authenticator. Send a valid DeregistrationRequest with "keyID" field set to empty string, wait for the response, and check that request succeeds. Send a valid authentication request, wait for the response, and check that API returns a NO_SUITABLE_AUTHENTICATOR(0x05) error   

    `, () => {
       let regMessageTemplate;
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((data) => {
                regMessageTemplate = data;
                regMessageTemplate[0].username = generateRandomString(15);
                let uafmessage = {'uafProtocolMessage' : JSON.stringify(regMessageTemplate)}
                return expectProcessUAFOperationSucceed(uafmessage)
            })
            .then((data) => {
                regMessageTemplate[0].username = generateRandomString(15);
                let uafmessage = {'uafProtocolMessage' : JSON.stringify(regMessageTemplate)}
                return expectProcessUAFOperationSucceed(uafmessage)
            })
            .then((data) => {
                regMessageTemplate[0].username = generateRandomString(15);
                let uafmessage = {'uafProtocolMessage' : JSON.stringify(regMessageTemplate)}
                return expectProcessUAFOperationSucceed(uafmessage)
            })
            .then(() => {
                return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            })
            .then((data) => {
                data[0].authenticators = [
                    {
                        'aaid': config.test.metadataStatement.aaid,
                        'keyID': ''
                    }
                ];
                
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
            .then(() => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
            })
            .then((data) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x05, `Expected NO_SUITABLE_AUTHENTICATOR(0x05) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })


    it(`P-4

        Send DeregistrationRequest with "authenticator" SEQUENCE containing "DeregistrationRequest" with "aaid" field set to the unknown AAID, wait for the response, and check that request succeeds.

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].authenticators = [
                    {
                        'aaid': 'FFFF#FFFF',
                        'keyID': base64url.encode(generateRandomBuffer(32))
                    }
                ];

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
    })

/* ---------- Negative Tests ---------- */
    describe(`F-1

        Send two DeregistrationRequests with "authenticator" SEQUENCE containing "DeregistrationRequest" with "aaid" field set to "undefined" and "null" correspondingly, wait for the responses, and check that API returns a PROTOCOL_ERROR(0x06) error for each of the response

    `, () => {
        it('authenticators[].aaid is undefined', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].authenticators = deregistrationAuthenticators;
                    data[0].authenticators[0].aaid = undefined

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('authenticators[].aaid is null', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].authenticators = deregistrationAuthenticators;
                    data[0].authenticators[0].aaid = null

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

        Send DeregistrationRequest with "authenticator" SEQUENCE containing "DeregistrationRequest" with "aaid" field is NOT of type DOMString, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error  

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].authenticators = deregistrationAuthenticators;
                data[0].authenticators[0].aaid = 0xdeadbeef

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-3

        Send DeregistrationRequest with "authenticator" SEQUENCE containing "DeregistrationRequest" with "aaid" field set to invalid AAID format(does NOT match /^[0-9A-Fa-f]{4}#[0-9A-Fa-f]{4}$/ regex pattern), wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error    

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].authenticators = deregistrationAuthenticators;
                data[0].authenticators[0].aaid = 'THIS#ROCK';

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

        Send two DeregistrationRequests with "authenticator" SEQUENCE containing "DeregistrationRequest" with "keyID" field set to "undefined" and "null" correspondingly, wait for the responses, and check that API returns a PROTOCOL_ERROR(0x06) error for each of the response 

    `, () => {
        it('authenticators[].keyID is undefined', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].authenticators = deregistrationAuthenticators;
                    data[0].authenticators[0].keyID = undefined

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        })

        it('authenticators[].keyID is null', () => {
            return getTestStaticJSON(`Protocol-Dereg-Req-P`)
                .then((data) => {
                    data[0].authenticators = deregistrationAuthenticators;
                    data[0].authenticators[0].keyID = null

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

        Send DeregistrationRequest with "authenticator" SEQUENCE containing "DeregistrationRequest" with "keyID" field is NOT of type DOMString, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].authenticators = deregistrationAuthenticators;
                data[0].authenticators[0].keyID = 0xdeadb00b;

                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(data),
                }

                return expectProcessUAFOperationFail(uafmessage);
            })
            .then((errorCode) => {
                assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
            })
    })

    it(`F-6

        Send DeregistrationRequest with "authenticator" SEQUENCE containing "DeregistrationRequest" with "keyID" field is NOT Base64URL encoded, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error 

    `, () => {
        return getTestStaticJSON(`Protocol-Dereg-Req-P`)
            .then((data) => {
                data[0].authenticators = deregistrationAuthenticators;
                data[0].authenticators[0].keyID = btoa(generateRandomString(16));

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
