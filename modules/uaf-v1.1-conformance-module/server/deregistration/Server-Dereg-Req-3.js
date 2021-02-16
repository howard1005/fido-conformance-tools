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

        Server-Dereg-Req-3

        Test the OperationHeader dictionary

    `, function() {

    let deregistrationRequest;
    before(() => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((response) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.deregister.get(1200, username))
            .then((data) => {
                deregistrationRequest = data[0];
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    });

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        OperationHeader must contain "upv" field, of type Dictionary, and: 
            (a) must contain key "major" with value 1 
            (a) must contain key "minor" with value 1

    `, () => {
        assert.isObject(deregistrationRequest.header.upv, 'UPV MUST be of type Dictionary');
        assert.strictEqual(deregistrationRequest.header.upv.major, 1, 'UPV.major MUST be set to 1!');
        assert.strictEqual(deregistrationRequest.header.upv.minor, 1, 'UPV.minor MUST be set to 1!');
    })

    it(`P-2

        Operation header must contain "op" field, of type DOMString, and: 
            (a) op must equal to "Dereg" member of the Operation enum

    `, () => {
        assert.isString(deregistrationRequest.header.op, 'UPV MUST be of type Dictionary');
        assert.strictEqual(deregistrationRequest.header.op, 'Dereg', 'Operation MUST be set to "Dereg"');
    })

    it(`P-3

        If OperationHeader contains "appID" field, it must be: 
            (a) of type DOMString 
            (b) it maximum length must be 512 characters 
            (c) it must be HTTPS URL 
            (d) if appID contains URL path(https://example.com/path/some/where) then: 
            (1) Try JSON fetching appID 
            (2) If URL returns (HTTP 3XX code) check that "FIDO-AppID-Redirect-Authorized" header set to true 
            (3) JSON parse TrustedFacetList DICTIONARY 
            (4) Check that trustedFacets key is of type SEQUENCE 
            (5) For each TrustedFacet in the trustedFacets check that: 
            (i) "TrustedFacet.version" is of type DICTIONARY 
            (ii) "TrustedFacet.major" is of type NUMBER 
            (iii) "TrustedFacet.minor" is of type NUMBER 
            (iv) "TrustedFacet.ids" is of type SEQUENCE 
            (iv) For each facetID in "TrustedFacet.ids" check that it's of type DOMString, and starts with either "https://", "android:apk-key-hash:" or "ios:bundle-id:"

    `, () => {
        if (deregistrationRequest.header.appID) {
            assert.isString(deregistrationRequest.header.appID, 'appID MUST be of type DOMString!');
            assert.isAtMost(deregistrationRequest.header.appID.length, 512, 'appID can be max of 512 characters long!');

            assert.isTrue(deregistrationRequest.header.appID.startsWith('https://'), 'appID MUST be a HTTPS URL!');

            if(breakURL(deregistrationRequest.header.appID).path) {
                fetch(deregistrationRequest.header.appID)
                    .then((response) => {
                        if(deregistrationRequest.header.appID !== response.url) {
                            console.log(`Detected redirection from "${deregistrationRequest.header.appID}" to "${response.url}"`);
                            return navigator.fido.uafv11.getFIDORedirectHeader(deregistrationRequest.header.appID)
                                .then((result) => {
                                    assert.strictEqual(result, 'true', 'If server is redirecting to other URL, FIDO-AppID-Redirect-Authorized MUST be set to "true"!');

                                    return response.json()
                                })

                        }
                        return response.json()
                    })
                    .then((TrustedFacetList) => {
                        assert.isArray(TrustedFacetList.trustedFacets, 'trustedFacets MUST be of type SEQUENCE');

                        for(let trustedFacet of TrustedFacetList.trustedFacets) {
                            assert.isObject(trustedFacet.version, 'Version MUST be of type DICTIONARY!')
                            assert.isNumber(trustedFacet.version.major, 'Version.major MUST be of type NUMBER!');
                            assert.isNumber(trustedFacet.version.minor, 'Version.minor MUST be of type NUMBER!');
                            assert.isArray(trustedFacet.ids, 'IDs MUST be of type SEQUENCE!');

                            for(let id of trustedFacet.ids) {
                                assert.isString(id, 'ID MUST only contain items of type DOMString!');

                                let isHTTPSURL = id.startsWith('https://');
                                let isIOSBundleID = id.startsWith('ios:bundle-id:');
                                let isAndroidAPKKeyHash = id.startsWith('android:apk-key-hash:');

                                assert.isTrue(isHTTPSURL || isIOSBundleID || isAndroidAPKKeyHash, 'ID MUST be either HTTPS URL, iOS BundleID URI or Android APK Key Hash URI!');
                            }
                        }
                    })

            }
        }
    })

    it(`P-4

        If OperationHeader contains "serverData" field, it must be: 
            (a) of type DOMString 
            (b) it minimum length must be 1 character 
            (c) it maximum length must be 1536 characters

    `, () => {
        if(deregistrationRequest.header.serverData) {
            assert.isString(deregistrationRequest.header.serverData, 'serverData MUST be of type DOMString!');
            assert.isAtLeast(deregistrationRequest.header.serverData.length, 1, 'serverData MUST be at least 1 character long!');
            assert.isAtMost(deregistrationRequest.header.serverData.length, 1536, 'serverData can be max of 1536 characters long!');
        }
    })

    it(`P-5

        If OperationHeader contains "exts" field, it must be: 
            (a) of type SEQUENCE 
            (b) if it contains any members, each member must be: 
                (i) of type dictionary 
                (ii) must contain "id" field, of type DOMString, with minimum length 1 character, and maximum length 32 characters. 
                (iii) must contain "data" field, of type DOMString, and use base64url encoding 
                (iv) must contain "fail_if_unknown" field, of type Boolean

    `, () => {
        if(deregistrationRequest.header.exts) {
            assert.isArray(deregistrationRequest.header.exts, 'exts MUST be of type SEQUENCE!');
            
            for (let extension of deregistrationRequest.header.exts) {
                assert.isString(extension.id, 'Extension.id MUST be of type DOMString!');
                assert.isAtLeast(extension.id.length, 1, 'Extension.id MUST be at least 1 character long!');
                assert.isAtMost(extension.id.length, 32, 'Extension.id can be max of 32 characters long!');

                assert.isString(extension.data, 'Extension.data MUST be of type DOMString!');
                assert.match(extension.data, /^[a-zA-Z0-9_-]+$/, 'Extension.data MUST be base64URL(without padding) encoded!');

                assert.isBoolean(extension.fail_if_unknown, 'Extension.id MUST be of type DOMString!');
            }
        }
    })
})
