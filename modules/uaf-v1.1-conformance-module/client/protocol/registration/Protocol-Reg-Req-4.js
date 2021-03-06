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

        Protocol-Reg-Req-4

        Test Client correctly processing AppID and Facets in Registration Request

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

    let authToken = '';
    before(function() {
        this.timeout(30000);
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((response) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(response),
                }

                return authenticator.processUAFOperation(uafmessage)
            })
            .then((response) => {
                let registrationReponse = tryDecodeJSON(response.uafProtocolMessage)[0];
                let fcParams = tryDecodeJSON(B64URLToUTF8(registrationReponse.fcParams));
                let facetID = fcParams.facetID;

                return getFacetAndAppIDAuthToken(facetID)
            })
            .then((token) => {
                authToken = token;
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

/* ----- POSITIVE TESTS ----- */
    describe(`P-1

        Send three RegistrationRequest UAF messages for the given metadata statement, with "header.appID" field set to "null", "undefined" and "empty" DOMString correspondingly, wait for the responses, and check that each request succeeds  

    `, () => {
        it('appID is null', () => {
            return getTestStaticJSON('Protocol-Reg-Req-P')
                .then((message) => {
                    message[0].header.appID = null;

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(message),
                    }

                    return expectProcessUAFOperationSucceed(uafmessage);
                })
        })

        it('appID is undefined', () => {
            return getTestStaticJSON('Protocol-Reg-Req-P')
                .then((message) => {
                    message[0].header.appID = undefined;

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(message),
                    }

                    return expectProcessUAFOperationSucceed(uafmessage);
                })
        })

        it('appID is empty DOMString', () => {
            return getTestStaticJSON('Protocol-Reg-Req-P')
                .then((message) => {
                    message[0].header.appID = '';

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(message),
                    }

                    return expectProcessUAFOperationSucceed(uafmessage);
                })
        })
    })

    it(`P-2

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" field set to the current facet, wait for the response, and check that request succeeds

    `)

    it(`P-3

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" field set to effective "https" URI that has the same effective domain as facetID(facet: https://example.com/login.html and appID: https://example.com/loginIsVerySecure), wait for the response, and check that request succeeds

    `)

    it(`P-4

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where current facetID is a member, wait for the response, and check that request succeeds

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'goodFacet')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationSucceed(uafmessage);
                    })
            })
    })

    it(`P-5

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with facetID set to the sub-domain of the appID(facetID:secure.example.com, appID:example.com), wait for the response and check that request succeeds

    `)

    it(`P-6

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the redirect(HTTP 3XX) to the trusted facets list, that has "FIDO-AppID-Redirect-Authorized" header set to "true", and current facetID is a member of the list, wait for the response and check that request succeeds

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'goodRedirect')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationSucceed(uafmessage);
                    })
            })
    })


/* ----- NEGATIVE TESTS ----- */
    it(`F-1

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where current facetID is NOT a member, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'missingCurrentFacet')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-2

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where "trustedFacets" key is missing, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'missingTrustedFacets')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-3

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where "trustedFacets" key is NOT of type SEQUENCE, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'badTrustedFacets')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-4

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where "trustedFacets" key is an empty SEQUENCE, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'emptyTrustedFacets')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-5

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where trustedFacets SEQUENCE contains TrustedFacet with missing "version" key, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'missingVersion')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-6

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where trustedFacets SEQUENCE contains TrustedFacet with "version" key is NOT of type DICTIONARY, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'badVersion')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-7

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where trustedFacets SEQUENCE contains TrustedFacet with "version.major" key is NOT of type NUMBER, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'badVersionMajor')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-8

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where trustedFacets SEQUENCE contains TrustedFacet with "version.minor" key is NOT of type NUMBER, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'badVersionMinor')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-9

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where trustedFacets SEQUENCE contains TrustedFacet with missing "ids" key, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'missingIDs')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-10

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where trustedFacets SEQUENCE contains TrustedFacet with "ids" key of type NOT SEQUENCE, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'badIDS')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-11

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, where trustedFacets SEQUENCE contains TrustedFacet with "ids" is set to empty SEQUENCE, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'emptyIDs')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-12

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" field set to appID with length that is larger than 512 characters(facet: https://example.com/VeryLoooooooo...ngAppID and appID: https://example.com/loginIsVerySecure), wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken, 'veryLongAppID')
            .then((appID) => {
                return getTestStaticJSON('Protocol-Reg-Req-P')
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x06, errorCode, `Expecting errorCode PROTOCOL_ERROR(0x06). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-13

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" field set to effective "http" URI that has the same effective domain as facetID(facet: http://example.com/login.html and appID: http://example.com/loginIsNotSoSecure), wait for the response, and check that API returns INSECURE_TRANSPORT(0x02) error

    `)

    it(`F-14

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" field set to the current facet, that is "http" URI, wait for the response, and check that API returns INSECURE_TRANSPORT(0x02) error

    `)

    it(`F-15

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" field set to the current facet, that is "https" URI, and contains insecure mixed content, wait for the response, and check that API returns INSECURE_TRANSPORT(0x02) error

    `)

    it(`F-16

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, and facetID is a sub-domain of the appID eTLD(effective top-level domain) and is NOT a member(e.g.: appID:https://example.com/facets.json and facetID: https://rogue.example.com) of trusted facet list, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `)

    it(`F-17

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the trusted facets list, and facetID is a "http" sub-domain of the appID eTLD(effective top-level domain) and is a member(e.g.: appID:https://example.com/facets.json and facetID: http://notsecure.example.com) of trusted facet list, wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `)

    it(`F-18

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI with domain that is second level eTLD(https://example.co.nz), that leads to the trusted facets list, that contain facet that is first level "https" eTLD in the same zone(https://attacker.nz), wait for the response, and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `)

    it(`F-19

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the redirect(HTTP 3XX) to the trusted facets list, that has "FIDO-AppID-Redirect-Authorized" missing, and current facetID is a member of the list, wait for the response and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'missingRedirectHeader')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-20

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the redirect(HTTP 3XX) to the trusted facets list, that has "FIDO-AppID-Redirect-Authorized" header set to "false", and current facetID is a member of the list, wait for the response and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'falseRedirectHeader')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-21

        Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the redirect(HTTP 3XX codes) to the trusted facets list, that has "FIDO-AppID-Redirect-Authorized" header set to NULL, and current facetID is a member of the list, wait for the response and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `, () => {
        return getFacetAndAppIDTestURL(authToken)
            .then((appID) => {
                return setAppIDTestCase(appID, 'nullRedirectHeader')
                    .then(() => getTestStaticJSON('Protocol-Reg-Req-P'))
                    .then((message) => {
                        message[0].header.appID = appID

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(message),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.strictEqual(0x07, errorCode, `Expecting errorCode UNTRUSTED_FACET_ID(0x07). Got: ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`);
                    })
            })
    })

    it(`F-22

        If testing DOM JS API: Send RegistrationRequest UAF message for the given metadata statement, with "header.appID" set to the "https" URI that leads to the redirect(HTTP 3XX codes) to the trusted facets list, that has "FIDO-AppID-Redirect-Authorized" header set to "true", and current facetID is a member of the list, but facetID and appID are do no share the same eTLD(facetID:example.com, redirected-appID:someSite.com) wait for the response and check that API returns UNTRUSTED_FACET_ID(0x07) error

    `)
})
