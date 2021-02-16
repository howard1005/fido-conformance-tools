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

        Server-Register-Req-1

        Test server generating U2F register request

    `, function() {

    this.timeout(10000);
    // this.retries(3);

    let identity = generateRandomIdentity()

/* ---------- Positive Tests ---------- */
    let appId = "";

    it(`P-1
            
        Send a valid Registration request, and check that server successfully returns a response, that contains such fields:
            a) "status" is of type DOMString and set to "ok"
            b) "errorMessage" is of type DOMString and is empty
            c) "appId" is of type DOMString.
            d) "registerRequests" is a sequence of RegisterRequest. Must not be empty. For each RegisterRequest check that:
                1) Check that "version" is of type DOMString, and is set to "U2F_V2"
                2) Check that "challenge" and is base64url encoded
            e) If present, check that "registeredKeys" is a sequence of RegisteredKey, and is empty(first register request).
            f) If present, check that "timeout" is of type Number.

    `, () => {
        return getRegister(identity)
            .then((response) => {
                assert.strictEqual(response.status, 'ok', 'Expected server response to return status code OK');
                assert.strictEqual(response.errorMessage, '', 'Expected "errorMessage" to be an empty string!');
                assert.isString(response.appId, 'Expected "errorMessage" to be an empty string!');
                appId = response.appId;
                assert.isArray(response.registerRequests, 'Expected "registerRequests" to be a Array!');
                assert.isNotEmpty(response.registerRequests, 'Expected "registerRequests" not to be empty!');

                for(let request of response.registerRequests) {
                    assert.isString(request.version, 'Expected "registerRequest.version" to be of type String');
                    assert.strictEqual(request.version, 'U2F_V2', 'Expected "registerRequest.version" to be set to "U2F_V2"!');
                    assert.isString(request.challenge, 'Expected "registerRequest.challenge" to be of type String');
                    assert.isNotEmpty(request.challenge, 'Expected "registerRequest.challenge" not to be empty!');
                    assert.match(request.challenge, /^[a-zA-Z0-9_-]+$/, 'Expected "registerRequest.challenge" to be base64URL(without padding) encoded!');
                }

                if(response.registeredKeys) {
                    assert.isArray(response.registeredKeys, 'Expected "registeredKeys" to be a Array!');
                    assert.isEmpty(response.registeredKeys, 'Expected "registeredKeys" to be empty!');
                }

                if(response.timeout) {
                    assert.isNumber(response.timeout, 'Expected "timeout" to be a Number!');
                }
            })
    })

    it(`P-2

        If request contains "appID" field, it must be: 
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
        if (appId) {
            assert.isString(appId, 'appID MUST be of type DOMString!');
            assert.isAtMost(appId.length, 512, 'appID can be max of 512 characters long!');

            assert.isTrue(appId.startsWith('https://'), 'appID MUST be a HTTPS URL!');

            if(breakURL(appId).path) {
                return fetch(appId)
                .then((response) => {
                    if(appId !== response.url) {
                        console.log(`Detected redirection from "${appId}" to "${response.url}"`);
                        return navigator.fido.uafv11.getFIDORedirectHeader(appId)
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

})
