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

        FC-API-Android-1

        Test the FIDO Android API for specification defined behaviour.

    `, function() {

    this.timeout(30000);
    this.retries(3);

    let ErrorCode = {
       'NO_ERROR': 0x0,
       'WAIT_USER_ACTION': 0x1,
       'INSECURE_TRANSPORT': 0x2,
       'USER_CANCELLED': 0x3,
       'UNSUPPORTED_VERSION': 0x4,
       'NO_SUITABLE_AUTHENTICATOR': 0x5,
       'PROTOCOL_ERROR': 0x6,
       'UNTRUSTED_FACET_ID': 0x7,
       'UNKNOWN': 0xFF
    }

    let metadata = window.config.test.metadataStatement;

/* ---------- Positive Tests ---------- */
    it(`P-1
        
        Call PackageManager.queryIntentActivities() or call PackageManager.queryIntentServices() and check that the FIDO Client under test is included in the returned list (type attribute needs to be set to application/fido.uaf_client+json).

        The vendor of the FIDO Client under test can specify which of the alternatives is/are supported.

    `, () => {
        return authenticator.getClientList()
            .then((list) => {
                assert.include(list, window.config.test.packageName, `Application ${window.config.test.packageName} is not in the list of application that supporting UAF Client Intent API!`)
            })        
    })

    it(`P-2
        
        Invoke the FIDO Client providing a valid DISCOVER request as uafRequest parameter and check that 
            (a) the call succeeds and that
            (b) the uafResponseListener provided as second parameter is called with a DISCOVER_RESULT parameter.
            (с) Check that the resultCode is RESULT_OK and that intent extra errorCode is NO_ERROR.

    `, () => {
        return authenticator.discover()
            .then((response) => {
                assert.isObject(response, 'DISCOVER_RESULT MUST be of type Object!');
            })
    })

    it(`P-3
        
        Check DiscoveryData.

        Check the DISCOVER_RESULT object received by previous test:
            (1) check that supportedUAFVersions field includes the current UAF protocol version.
            (2) check that field clientVendor is as expected (i.e. identical to vendor name specified in test).
            (3) check that clientVersion is as expected (i.e. the version intended to be tested).
            (4) check that an availableAuthenticators list is provided (might be empty).

    `, () => {
        return authenticator.discover()
            .then((response) => {
                /**
                 * Checking supportedVersion
                 */
                let supportedVersion = `${config.manifesto.defaults.currentUAFVersion.minor}:${config.manifesto.defaults.currentUAFVersion.major}`;
                let versionPresented = false;

                for(let version of response.supportedUAFVersions) {
                    if(`${version.minor}:${version.major}` === supportedVersion) {
                        versionPresented = true;
                        break
                    }
                }
                
                assert.isTrue(versionPresented, 'Supported version in the list.');
                
                /**
                 * Checking clientVendor
                 */
                assert.equal(response.clientVendor, window.config.test.clientVendor, 
                            `clientVendor field is identical to vendor name specified in test config`)

                /**
                 * Checking clientVersion
                 */
                assert.equal(`${response.clientVersion.major}:${response.clientVersion.minor}`,
                             `${window.config.test.clientVersion.major}:${window.config.test.clientVersion.minor}`,
                             `clientVersion is identical to the clientVersion that specified in test window.config.test.`)

                assert.isArray(response.availableAuthenticators,
                            'availableAuthenticators list is provided (might be empty)');
                
            })
    })

    it(`P-4
        
        Call function "process" providing a valid DISCOVER request as uafRequest parameter and check that
            (a) the call succeeds and that
            (b) the uafResponseListener provided as second parameter is called with a DISCOVER_RESULT parameter. Check all elements included in availableAuthenticators as follows:
                (1) check that all mandatory fields are present.
                (2) Check that the fields title, AAID, assertionScheme, authenticationAlgorithm, attestationTypes, userVerification, keyProtection, matcherProtection, attachmentHint, isSecondFactorOnly, tcDisplay, tcDisplayContentType, tcDisplayPNGCharacteristics, icon and supportedExtensionIDs are as specified for this authenticator model
                
    `, () => {
        return authenticator.discover()
            .then((response) => {
                for(let authenticator of response.availableAuthenticators) {
                    if(authenticator.aaid === metadata.aaid) {

                        assert.isDefined(authenticator.supportedUAFVersions, 'AuthenticatorInfo missing supportedUAFVersions field!');
                        assert.isArray(authenticator.supportedUAFVersions, 'AuthenticatorInfo.supportedUAFVersions is not of type SEQUENCE!');
                        assert.isNotEmpty(authenticator.supportedUAFVersions, 'AuthenticatorInfo.supportedUAFVersions can NOT be empty!');
                        for(let asmVersion of authenticator.supportedUAFVersions) {
                            assert.isObject(asmVersion, 'Version MUST be of type OBJECT!');
                            assert.isDefined(asmVersion.major, 'Version MUST contain "major" key!');
                            assert.isNumber(asmVersion.major, 'Version.major MUST be of type Number!');
                            assert.isDefined(asmVersion.minor, 'Version MUST contain "minor" key!');
                            assert.isNumber(asmVersion.minor, 'Version.minor MUST be of type Number!');
                        }
                        assert.deepInclude(authenticator.supportedUAFVersions, { 'major':1, 'minor':1 }, 'AuthenticatorInfo.supportedUAFVersions MUST include v1.1!');

                        assert.isDefined(authenticator.aaid, 'AuthenticatorInfo missing aaid field!');
                        assert.isString(authenticator.aaid, 'AuthenticatorInfo.aaid is not of type STRING!');
                        assert.match(authenticator.aaid, /^[a-fA-F0-9]{4}#[a-fA-F0-9]{4}$/, `aaid ${authenticator.aaid} is not in format {2 byte encoded in HEX}#{2 byte encoded in HEX}!`);

                        assert.isDefined(authenticator.assertionScheme, 'AuthenticatorInfo missing assertionScheme field!');
                        assert.isString(authenticator.assertionScheme, 'AuthenticatorInfo.assertionScheme is not of type STRING!');
                        assert.strictEqual(authenticator.assertionScheme, 'UAFV1TLV', 'AuthenticatorInfo.assertionScheme MUST be set to UAFV1TLV!');

                        assert.isDefined(authenticator.attestationTypes, 'AuthenticatorInfo missing attestationTypes field!');
                        assert.isArray(authenticator.attestationTypes, 'AuthenticatorInfo.attestationTypes is not of type SEQUENCE');
                        assert.deepEqual(authenticator.attestationTypes, metadata.attestationTypes, 'AuthenticatorInfo.attestationTypes MUST match MetadataStatement.attestationTypes!');

                        assert.isDefined(authenticator.authenticationAlgorithm, 'AuthenticatorInfo missing authenticationAlgorithm field!');
                        assert.isNumber(authenticator.authenticationAlgorithm, 'AuthenticatorInfo.authenticationAlgorithm is not of type Number!');
                        assert.strictEqual(authenticator.authenticationAlgorithm, metadata.authenticationAlgorithm, 'AuthenticatorInfo.authenticationAlgorithm MUST match MetadataStatement.authenticationAlgorithm!');

                        assert.isDefined(authenticator.userVerification, 'AuthenticatorInfo missing userVerification field!');
                        assert.isNumber(authenticator.userVerification, 'AuthenticatorInfo.userVerification is not of type Number!');

                        assert.include(getMetadataUserVerificationCombos(), authenticator.userVerification, 'MetadataStatement.userVerificationDetails AND combos MUST contain AuthenticatorInfo.userVerification!');

                        assert.isDefined(authenticator.keyProtection, 'AuthenticatorInfo missing keyProtection field!');
                        assert.isNumber(authenticator.keyProtection, 'AuthenticatorInfo.keyProtection is not of type Number!');
                        assert.strictEqual(authenticator.keyProtection, metadata.keyProtection, 'AuthenticatorInfo.keyProtection MUST match MetadataStatement.keyProtection!');

                        assert.isDefined(authenticator.matcherProtection, 'AuthenticatorInfo missing matcherProtection field!');
                        assert.isNumber(authenticator.matcherProtection, 'AuthenticatorInfo.matcherProtection is not of type Number!');
                        assert.strictEqual(authenticator.matcherProtection, metadata.matcherProtection, 'AuthenticatorInfo.matcherProtection MUST match MetadataStatement.matcherProtection!');

                        assert.isDefined(authenticator.attachmentHint, 'AuthenticatorInfo missing attachmentHint field!');
                        assert.isNumber(authenticator.attachmentHint, 'AuthenticatorInfo.attachmentHint is not of type Number!');
                        assert.strictEqual(authenticator.attachmentHint, metadata.attachmentHint, 'AuthenticatorInfo.attachmentHint MUST match MetadataStatement.attachmentHint!');

                        assert.isDefined(authenticator.isSecondFactorOnly, 'AuthenticatorInfo missing isSecondFactorOnly field!');
                        assert.isBoolean(authenticator.isSecondFactorOnly, 'AuthenticatorInfo.isSecondFactorOnly is not of type BOOLEAN');
                        assert.strictEqual(authenticator.isSecondFactorOnly, metadata.isSecondFactorOnly, 'AuthenticatorInfo.isSecondFactorOnly MUST match MetadataStatement.isSecondFactorOnly!');

                        assert.isDefined(authenticator.supportedExtensionIDs, 'AuthenticatorInfo missing supportedExtensionIDs field!');
                        assert.isArray(authenticator.supportedExtensionIDs, 'AuthenticatorInfo.supportedExtensionIDs is not of type SEQUENCE!');
                        for(let extensionID of authenticator.supportedExtensionIDs)
                            assert.isString(extensionID, 'ExtensionID MUST be of type STRING!');

                        assert.isDefined(authenticator.tcDisplay, 'AuthenticatorInfo missing tcDisplay field!');
                        assert.isNumber(authenticator.tcDisplay, 'AuthenticatorInfo.tcDisplay is not of type Number!');
                        assert.strictEqual(authenticator.tcDisplay, metadata.tcDisplay, 'AuthenticatorInfo.tcDisplay MUST match MetadataStatement.tcDisplay!');

                        if(authenticator.tcDisplay !== 0) {
                            assert.isString(authenticator.tcDisplayContentType, 'AuthenticatorInfo.tcDisplayContentType MUST be of type STRING!');
                            assert.strictEqual(authenticator.tcDisplayContentType, metadata.tcDisplayContentType, 'AuthenticatorInfo.tcDisplayContentType MUST match MetadataStatement.tcDisplayContentType!');

                            assert.deepEqual(authenticator.tcDisplayPNGCharacteristics, metadata.tcDisplayPNGCharacteristics, 'AuthenticatorInfo.tcDisplayPNGCharacteristics MUST match MetadataStatement.tcDisplayPNGCharacteristics!');
                        } else {
                            assert.isUndefined(authenticator.tcDisplayContentType, 'If AuthenticatorInfo.tcDisplay set to NO_DISPLAY(0), AuthenticatorInfo.tcDisplayContentType MUST be missing!');
                            assert.isUndefined(authenticator.tcDisplayPNGCharacteristics, 'If AuthenticatorInfo.tcDisplay set to NO_DISPLAY(0), AuthenticatorInfo.tcDisplayPNGCharacteristics MUST be missing!');
                        }

                        if(authenticator.title) {
                            assert.isString(authenticator.title, 'AuthenticatorInfo.title is not of type STRING!');
                            assert.isNotEmpty(authenticator.title, 'AuthenticatorInfo.title MUST not be empty!');
                        }

                        if(authenticator.description) {
                            assert.isString(authenticator.description, 'AuthenticatorInfo.description is not of type STRING!');
                            assert.isNotEmpty(authenticator.description, 'AuthenticatorInfo.description MUST not be empty!');
                        }

                        if(authenticator.icon) {
                            assert.isString(authenticator.icon, 'AuthenticatorInfo.icon is not of type STRING!');
                            assert.isNotEmpty(authenticator.icon, 'AuthenticatorInfo.icon MUST not be empty!');
                            assert.match(authenticator.icon, /^data:image\/png;base64,[A-Za-z0-9+/]+[=]{0,2}$/, 'AuthenticatorInfo.icon MUST be URL encoded PNG image!')
                        }

                        return
                    }
                }

                throw new Error(`DiscoveryData missing info for ${metadata.aaid}!`);
            })
    })

    it(`P-5
        
        Call function "process" providing valid a CHECK_POLICY request as uafRequest parameter and check that
            (a) the call succeeds and that
            (b) the uafResponseListener provided as second parameter is called with a CHECK_POLICY_RESULT parameter indicating policy match (i.e. resultCode=RESULT_OK and errorCode=NO_ERROR). Use the following policy: "accepted": [[{"aaid": "AAID-missing"}], [{"aaid": "AAID-present"}]]. Where "AAID-missing" refers to an authenticator model NOT available at that time and "AAID-present" refers to an authenticator model available to the FIDO Client at time of test.

    `, () => {
        return getTestStaticJSON('FC-API-Adroid-1-P-4')
            .then((response) => {
                let message = {
                    uafProtocolMessage: JSON.stringify(response),
                    additionalData: {}
                }

                return authenticator.checkPolicy(message)  
            })
            .then((errorCode) => {
                let errorMessage = '\n\CHECK_POLICY returned Fail type errorCode. Expecting Success errorCode of 0x0\n\n';
                assert.strictEqual(errorCode, ErrorCode.NO_ERROR, errorMessage);
            })
    })

    it(`P-6
        
        Call function "process" providing valid a UAF_OPERATION request (UAF registration request) as uafRequest parameter and check that
            (a) the call succeeds and that
            (b) the uafResponseListener provided as second parameter is called with a UAF_OPERATION_RESULT parameter indicating success.

    `, () => {
        return getTestStaticJSON('FC-API-Adroid-1-P-5')
            .then((response) => {
                let message = {
                    uafProtocolMessage: JSON.stringify(response),
                    additionalData: {}
                }

                return authenticator.processUAFOperation(message)
            })
    })

    it(`P-7
        Call function "process" providing valid a UAF_OPERATION request (UAF authentication request) as uafRequest parameter and check that
            (a) the call succeeds and that
            (b) the uafResponseListener provided as second parameter is called with a UAF_OPERATION_RESULT parameter indicating success.

    `, () => {
        return getTestStaticJSON('FC-API-Adroid-1-P-6')
            .then((response) => {
                let message = {
                    uafProtocolMessage: JSON.stringify(response),
                    additionalData: {}
                }

                return authenticator.processUAFOperation(message)
            })
    })

/* ---------- Negative Tests ---------- */
    it(`F-1
        
        Call function "process" providing valid a CHECK_POLICY request as uafRequest parameter and check that
            (a) the call succeeds and that
            (b) the uafResponseListener provided as second parameter is called with a CHECK_POLICY_RESULT parameter indicating no policy match (i.e. resultCode=RESULT_OK and errorCode=NO_SUITABLE_AUTHENTICATOR). Use the following policy: "accepted": [[{"aaid": "AAID-missing"}]]. Where "AAID-missing" refers to an authenticator model NOT available to the FIDO Client under test at that time.

    `, () => {
        return getTestStaticJSON('FC-API-Adroid-1-F-1')
            .then((response) => {
                response[0].policy.accepted = [
                    [{"aaid": [generateRandomAAID()]}]
                ]

                let message = {
                    uafProtocolMessage: JSON.stringify(response),
                    additionalData: {}
                }

                return authenticator.checkPolicy(message)  
            })
            .then((errorCode) => {
                let errorMessage = '\n\CHECK_POLICY_RESULT returned Success errorCode. Expecting Fail errorCode\n\n';
                assert.strictEqual(errorCode, ErrorCode.NO_SUITABLE_AUTHENTICATOR, errorMessage);
            })
    })
})
