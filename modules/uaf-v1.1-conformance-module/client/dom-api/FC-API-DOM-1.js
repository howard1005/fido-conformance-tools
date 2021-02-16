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

        FC-API-DOM-1

        Test the FIDO DOM API for specification defined behaviour.

    `, function() {

    this.timeout(30000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1
        
            Check that "navigator.fido.uaf.discover()" method, can be invoked providing a valid DiscoveryData.

            Call function "navigator.fido.uaf.discover()", and ensure that "completionCallback" receives is a valid "DiscoveryData".

        `, function(done) {
                window.navigator.fido.uaf.discover(
                    /**
                     * completionCallback
                     */
                    (response) => {

                        let scheme = {
                            type : 'object',
                            properties : {
                                availableAuthenticators : {
                                    type : 'array'
                                },
                                clientVendor : {
                                    type : 'string'
                                },
                                clientVersion : {
                                    type : 'object'
                                },
                                supportedUAFVersions : {
                                    type : 'array'
                                }
                            },
                            required : [
                                'availableAuthenticators',
                                'clientVendor',
                                'clientVersion',
                                'supportedUAFVersions'
                            ]
                        }

                        let result = validateDataAgainstScheme(response, scheme);
                        assert.isTrue(result.valid, result.errorMessages);

                        done();
                    },

                    /**
                     * errorCallback
                     */
                    (error) => {
                        done(new Error(`Error durring processing discover() request. Error code ${INTERFACE_ERROR_CODES[error]}`));
                    }
                )
    })

    it(`P-2
        
        Check DiscoveryData.

        Check that "navigator.fido.uaf.discover()" method's discoveryData: 
            (1) check that supportedUAFVersions field includes the current UAF protocol version. 
            (2) check that field clientVendor is as expected (i.e. identical to vendor name specified in test). 
            (3) check that clientVersion is as expected (i.e. the version intended to be tested). 
            (4) check that an availableAuthenticators list is provided (might be empty).

        `, function(done) {
            
            window.navigator.fido.uaf.discover(
                /**
                 *  completionCallback
                 */
                (response) => {

                    /**
                     * Checking supportedVersion
                     */
                    let supportedVersion = `${config.manifesto.defaults.currentUAFVersion.minor}:${config.manifesto.defaults.currentUAFVersion.major}`;
                    let versionPresented = false;

                    for(let version of response.supportedUAFVersions)
                        if(`${version.minor}:${version.major}` === supportedVersion) {
                            versionPresented = true;
                            break
                        }
                    
                    assert.isTrue(versionPresented, 'Supported version in the list.');
                    
                    /**
                     * Checking clientVendor
                     */
                    assert.equal(response.clientVendor, config.test.clientVendor, 
                                `clientVendor field is identical
                                to vendor name specified in test config`)

                    /**
                     * Checking clientVersion
                     */
                    assert.equal(`${response.clientVersion.minor}:${response.clientVersion.major}`,
                                 `${config.test.clientVersion.minor}:${config.test.clientVersion.major}`,
                                 `clientVersion is identical 
                                 to the clientVersion that specified in test config.test.`)
                    
                    assert.equal(type(response.availableAuthenticators), 'Array',
                        'availableAuthenticators list is provided (might be empty)');

                    done();

                },

                /**
                 * errorCallback
                 */
                (error) => {
                    done(new Error(`Error durring processing discover() request. Error code ${INTERFACE_ERROR_CODES[error]}`))
                }
            )

    })

    it(`P-3
        
        Call function "navigator.fido.uaf.discover()" that
            (a) the call succeeds and that
            (b) and that the discoveryData returned in the callback.

        Check all elements included in discoveryData.availableAuthenticators as follows: 
            (1) check that all mandatory fields are present. 
            (2) Check that the fields title, AAID, assertionScheme, authenticationAlgorithm, attestationTypes, userVerification, keyProtection, matcherProtection, attachmentHint, isSecondFactorOnly, tcDisplay, tcDisplayContentType, tcDisplayPNGCharacteristics, icon and supportedExtensionIDs are as specified for this authenticator model.

        `, function(done) {
            
            window.navigator.fido.uaf.discover(
                /**
                 * completionCallback
                 */
                (response) => {

                    let scheme = {   
                        type  : 'object',
                        allOf : [{ 
                                $ref : 'DiscoveryData.scheme.json#/definitions/DiscoveryData'
                            }]
                    }

                    let result = validateDataAgainstScheme(response, scheme);

                    assert.isTrue(result.valid, result.errorMessages);

                    done();
                },

                /**
                 * errorCallback
                 */
                (error) => {
                    done(new Error(`Error durring processing discover() request. Error code ${INTERFACE_ERROR_CODES[error]}`))
                }
            )

    })

    it(`P-4
        
        Check "navigator.fido.uaf.checkPolicy()" function when (at least) one authenticator is present

    `, function(done) {
        getTestStaticJSON('FC-API-DOM-1-P-4')
            .then((response) => {
                let errorMessage = '\n\ncheckPolicy returned Fail type errorCode. Expecting Success errorCode of 0x0\n\n';

                let message = {
                    uafProtocolMessage: JSON.stringify(response),
                    additionalData: {}
                }

                 window.navigator.fido.uaf.checkPolicy(
                    message,

                    (errorCode) => {
                        assert.strictEqual(errorCode, 0x0, errorMessage);

                        done();
                    }
                )
            })
    })

    it(`P-5
        
        Check "navigator.fido.uaf.processUAFOperation()" function when (at least) one authenticator is present.

        Call function "navigator.fido.uaf.processUAFOperation()" providing a valid REGISTRATION UAFMessage, and check that: 
            (a) the call succeeds and that the UAFResponseCallback was called 
            (b) the UAFResponseCallback returned valid UAFMessage

    `, function(done) {

        getTestStaticJSON('FC-API-DOM-1-P-5')
            .then((response) => {

                let message = {
                    uafProtocolMessage: JSON.stringify(response),
                    additionalData: {}
                }

                 window.navigator.fido.uaf.processUAFOperation(
                    message,

                    /**
                     * completionCallback
                     */
                    (response) => {
                        let assertion = tryDecodeJSON(response.uafProtocolMessage);
                        let scheme = {
                            type  : 'array',
                            items : {
                                $ref : 'Responses.scheme.json#/definitions/RegistrationResponse'
                            }
                        }

                        let result = validateDataAgainstScheme(assertion, scheme);
                        assert.isTrue(result.valid, result.errorMessages);

                        done();
                    },

                     /**
                     * errorCallback
                     */
                    (error) => {
                        done(new Error(`Error durring processing processUAFOperation() request. Error code ${INTERFACE_ERROR_CODES[error]}`));
                    }
                );
            })
    })

    it(`P-6
        Check "navigator.fido.uaf.processUAFOperation()" function when (at least) one authenticator is present

        Call function "navigator.fido.uaf.processUAFOperation()" providing a valid authentication UAFMessage, and check that: 
            (a) the call succeeds and that the UAFResponseCallback was called 
            (b) the UAFResponseCallback returned valid UAFMessage

    `, function(done) {

        getTestStaticJSON('FC-API-DOM-1-P-6')
            .then((response) => {
                let message = {
                    uafProtocolMessage: JSON.stringify(response),
                    additionalData: {}
                }

                 window.navigator.fido.uaf.processUAFOperation(
                    message,

                    /**
                     * completionCallback
                     */
                    (response) => {
                        let assertion = tryDecodeJSON(response.uafProtocolMessage);
                        let scheme = {
                            type  : 'array',
                            items : {
                                $ref : 'Responses.scheme.json#/definitions/AuthenticationResponse'
                            }
                        }

                        let result = validateDataAgainstScheme(assertion, scheme);

                        assert.isTrue(result.valid, result.errorMessages);

                        done();
                    },

                    /**
                     * errorCallback
                     */
                    (error) => {
                        done(new Error(`Error durring processing processUAFOperation() request. Error code ${INTERFACE_ERROR_CODES[error]}`))
                    }
                );
            })
    })

    it(`P-7

        Check "navigator.fido.uaf.notifyUAFResult()" function when (at least) one authenticator is present

        Section 4.5 + 5.2.1 + 5.3 [[!UAFAppAPIAndTransport]] 
            (a) Check the type of "navigator.fido.uaf.notifyUAFResult" to be function.
            (b) Call function "navigator.fido.uaf.notifyUAFResult()", and ensure that no callbacks been called.

    `, function(done) {
        getTestStaticJSON('FC-API-DOM-1-P-7')
            .then((response) => {
                let message = {
                    uafProtocolMessage: JSON.stringify(response),
                    additionalData: {}
                }

                 window.navigator.fido.uaf.notifyUAFResult(
                    1200,
                    message
                );

                done();
            })
    })

/* ---------- Negative Tests ---------- */
    it(`F-1
        
        Check "navigator.fido.uaf.checkPolicy()" function when (at least) one authenticator is present(non-matching policy)

    `, function() {

        getTestStaticJSON('FC-API-DOM-1-F-1')
            .then((response) => {
                let errorMessage = '\n\ncheckPolicy returned Success errorCode. Expecting Fail errorCode\n\n';

                response[0].policy.accepted = [];

                let message = {
                    uafProtocolMessage: JSON.stringify(response),
                    additionalData: {}
                }

                 window.navigator.fido.uaf.checkPolicy(
                    message,

                    (errorCode) => {
                        assert.notStrictEqual(errorCode, 0x0, errorMessage);

                        done();
                    }
                )
            })
    })
})
