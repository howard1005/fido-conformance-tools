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

(function(){

    /**
     * Node.js fix for localStorage
     */
    if(!window || !window.localStorage || !localStorage)
        var localStorage = {};

    /* ---------- HELPERS ---------- */
        /**
         * Checks if URL is HTTPS url
         * @param  {String} url - arbitrary URL
         * @return {Boolean}     - is HTTPS
         */
        let isHTTPS = (url) => url.startsWith('https://');

        /**
         * Checks if URL is HTTP url
         * @param  {String} url - arbitrary URL
         * @return {Boolean}     - is HTTP
         */
        let isHTTP = (url) => url.startsWith('http://');


        let getDomainAndProtocol = (url) => url.split(/^((https:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)(:\d{0,5})?)\/?/)[1];

        /**
         * Takes arbitrary URL and returns accessible URL object
         * @param  {String} url - arbitrary URL
         * @return {Object}     - URL object
         */
        let breakURL = (url) => {
            let args = url.split(/^((https?):\/\/)?([^:^\/]*):?(\d*)?(.*)?/);
            return {
                'protocol': args[2],
                'host'    : args[3],
                'port'    : args[4]
            }
        }

        /**
         * Take arbitrary URL and return true if it's a valid facetID
         * @param  {String}
         * @return {Boolean}
         */
        let isValidURLFacetID = (url) => /^((https:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)(:\d{0,5})?\/?)$/.test(url);
        
        /**
         * Take arbitrary URI and return true if it's a valid iOS facetID
         * @param  {String}
         * @return {Boolean}
         */
        let isValidBundleID = (uri) => /^ios:bundle-id:[a-z0-9-]+(.[a-z0-9-]+)+$/.test(uri);
        
        /**
         * Take arbitrary URI and return true if it's a valid android facetID
         * @param  {String}
         * @return {Boolean}
         */
        let isValidAndroidApkCertHash = (uri) => /^android:apk-key-hash:[\+\/\w]+$/.test(uri);

        let protocolVersion = {'major': 1,'minor': 0}
        /**
         * Verifies that given protocol version
         * @param   {Object} givenObject - given protocol version object
         * @return {Boolean}              - if given protocol version object matches required
         */
        let verifyProtocolVersion = (givenObject) => givenObject.major === protocolVersion.major && givenObject.minor === protocolVersion.minor;

    /* ---------- NO MORE HELPERS ---------- */

    /**
     * The Public Suffix List is an initiative of Mozilla, but is maintained as a community resource. It is available for use in any software, but was originally created to meet the needs of browser manufacturers. It allows browsers to, for example:
        * Avoid privacy-damaging "supercookies" being set for high-level domain name suffixes
        * Highlight the most important part of a domain name in the user interface
        * Accurately sort history entries by site
     * @type {String}
     */
    let publicsuffixURL = 'https://publicsuffix.org/list/effective_tld_names.dat'

    /**
     * Downloads public suffix list, and generates tld tree.
     * @return {Promise} - fetch promise
     */
    let downloadLatestActiveTLDList = () => {
        return fetch(publicsuffixURL)
            .then((result) => result.text())
            .then((result) => {
                let suffixes = {};

                let lines = result.split('\n')

                for(let line of lines) {

                    /**
                     * Comments and empty lines
                     */
                    if(line === '' || line.startsWith('//'))
                        continue

                    if(line.indexOf('.') === -1) {
                        if(!suffixes[line])
                            suffixes[line] = {};
                        else
                            console.error(`Dublicate tld found. ${line} exist!`);

                        continue
                    } else {
                        let subSuffixes = line.split('.').reverse();

                        let level = suffixes;
                        for(let subSuffix of subSuffixes) {
                            if(!level[subSuffix])
                                level[subSuffix] = {};
                            
                            level = level[subSuffix]
                        }
                    }
                }

                return suffixes
            })
    }

    /**
     * Verifies that given facetID is valid.
     * @param  {String} - Application ID
     * @param  {String} - Facet ID
     * @return {String} - Promise
     */
    let VerifyFacets = (appID, facetID) => {

        /**
         * Lowercasing inputs
         */
        appID   =   appID.toLocaleLowerCase();
        facetID = facetID.toLocaleLowerCase();

        return new Promise((resolve, reject) => {
            if (!localStorage['activeTLDsTree']) {
                downloadLatestActiveTLDList()
                    .then((result) => {
                        localStorage['activeTLDsTree'] = JSON.stringify(result)
                        resolve(result)
                    })
                    .catch((error) => reject(`Error while loading TLD list: ${error}`))
            } else {
                try {
                    let tldlist = tryDecodeJSON(localStorage['activeTLDsTree']);
                    resolve(tldlist)
                } catch (error) {
                    downloadLatestActiveTLDList()
                        .then((result) => {
                            localStorage['activeTLDsTree'] = JSON.stringify(result)
                            resolve(result)
                        })
                        .catch((error) => reject(`Error while loading TLD list: ${error}`))
                }
            }
        })
        .then((tldTree) => {
            return new Promise((resolve, reject) => {

                /**
                 * Returns lest specific domain name
                 * example A 'account.google.com' will return 'google.com'
                 * example B 'subsubsud.subsub.sub.example.co.za' will return 'example.co.za'
                 * @param  {String} url - given URL
                 * @return {String}     - least specific domain name
                 */
                let getLeastSpecificDomainName = (url) => {
                    let suffixes = breakURL(url)
                                    .host
                                    .split('.')
                                    .reverse();

                    let level = tldTree;
                    let domain = '';

                    for(let suffix of suffixes) {
                        if(domain)
                            domain = '.' + domain;

                        domain = suffix + domain;

                        if(level[suffix]) {
                            level  = level[suffix];
                        } else {
                            break
                        }
                    }

                    return domain
                }

                /**
                 * Returns if TLD exists
                 * @param  {String} url - given URL
                 * @return {Boolena}    - if TLD exists
                 */
                let tldExists = (url) => {
                    let suffixes = breakURL(url)
                                    .host
                                    .split('.')

                    return !!tldTree[suffixes.pop()]
                }

                /**
                 * Entries in ids using the https:// scheme must contain only scheme, host and port components, with an optional trailing /. Any path, query string, username/password, or fragment information must be discarded.
                 */
               
                /**
                 * Takes array of Facets and returns array of valid facets
                 * @param  {Array} facets - facets to validate
                 * @return {Array}        - valid facets
                 */
                let filterFacets = (facets) => {
                    let validFacets = [];

                    for(let facet of facets) {

                        /**
                         * Lowercasing inputs
                         */
                        facet = facet.toLocaleLowerCase();

                        if(isHTTP(facet)) {
                            console.log(`Facet "${facet}" is not a trusted facet. Reason: HTTP host`)
                            continue
                        }

                        if(isValidBundleID(facet) || isValidAndroidApkCertHash(facet)) {
                            validFacets.push(facet)
                            continue
                        }

                        if(isHTTPS(facet)) {
                            let appIDHost = getLeastSpecificDomainName(appID);
                            let facetHost = breakURL(facet).host;

                            if(facetHost.indexOf(appIDHost) !== -1) {
                                let subDomain = facetHost.replace(`.${appIDHost}`, '');
                                if(`${subDomain}.${appIDHost}` === facetHost){
                                    validFacets.push(facetHost);
                                    continue;
                                } else {
                                    console.log(`Facet "${facet}" is not a trusted facet. Reason: ${facet} is not a subDomain of a ${appIDHost}`);

                                }
                            } else {
                                console.log(`Facet "${facet}" is not a trusted facet. Reason: ${facet} is not a subDomain of a ${appIDHost}`);
                            }
                        }
                    }

                    return validFacets;
                }

                /**
                 * FacetID must be provided
                 */
                if(!facetID)
                    throw new Error('FacetID is empty or undefined!')

                /**
                 * 2. If the AppID is null or empty, the client must set the AppID to be the FacetID of the caller, and the operation may proceed without additional processing.
                 */
                if(appID === null || appID === '' || appID === undefined)
                    appID = facetID;

                let appIDFacet   = getDomainAndProtocol(appID);
                let facetIDFacet = getDomainAndProtocol(facetID);

                if(!isHTTPS(appIDFacet)) {
                    /**
                     * 1. If the AppID is not an HTTPS URL, and matches the FacetID of the caller, no additional processing is necessary and the operation may proceed.
                     */
                    if(appIDFacet === appID && appID === facetID)
                        resolve(`AppID is not an HTTPS URL, and matches the FacetID of the caller`);
                    else
                        reject(new Error('appID is NOT HTTPS URL, and it does not match facetID!'));
                } else {
                    /**
                     * 3. If the caller's FacetID is an https:// Origin sharing the same host as the AppID, (e.g. if an application hosted at https://fido.example.com/myApp set an AppID of https://fido.example.com/myAppId), no additional processing is necessary and the operation may proceed. This algorithm may be continued asynchronously for purposes of caching the Trusted Facet List, if desired.
                     */
                    if(appIDFacet === facetIDFacet)
                        resolve(`Caller's FacetID is an https:// Origin sharing the same host as the AppID`);
                    else {

                        /**
                         * Begin to fetch the Trusted Facet List using the HTTP GET method. The location must be identified with an HTTPS URL.
                         * The URL must be dereferenced with an anonymous fetch. That is, the HTTP GET must include no cookies, authentication, Origin or Referer headers, and present no TLS certificates or other forms of credentials.
                         */
                        fetch(appID)
                            .then((response) => {
                                /**
                                 * The response must set a MIME Content-Type of "application/fido.trusted-apps+json".
                                 */
                                if(response.headers.get('Content-Type') === 'application/fido.trusted-apps+json'
                                || response.headers.get('Content-Type') === 'application/json') { // Still compliant
                                    if(response.redirect) {
                                        /**
                                         * 9. If the server returns an HTTP redirect (status code 3xx) the server must also send the HTTP header FIDO-AppID-Redirect-Authorized: true and the client must verify the presence of such a header before following the redirect. This protects against abuse of open redirectors within the target domain by unauthorized parties. If this check has passed, restart this algorithm from step 4.
                                         */
                                        if(response.headers.get('FIDO-AppID-Redirect-Authorized') === 'true') {
                                            VerifyFacets(response.url, facetID)
                                                .then((response) => resolve(response))
                                                .catch((error) => reject(error))
                                        } else 
                                            reject(new Error('Redirected request MUST have FIDO-AppID-Redirect-Authorized header be set to true'))
                                    } else {
                                        return response.json()
                                    }
                                } else
                                    reject(new Error('The response must set a MIME Content-Type of "application/fido.trusted-apps+json"'))
                            })
                            .then((response) => {
                                let ids;

                                for(let trustedFacet of response.trustedFacets) {
                                    if(verifyProtocolVersion(trustedFacet.version)) {
                                        ids = trustedFacet.ids;
                                        break
                                    }
                                }

                                if(!ids)
                                    reject(`No TrustedFacets with protocol version ${protocolVersion.major}.${protocolVersion.minor} found!`);

                                /**
                                 * Entries in ids using the https:// scheme must contain only scheme, host and port components, with an optional trailing /. Any path, query string, username/password, or fragment information must be discarded.
                                 * 
                                 * All Web Origins listed must have host names under the scope of the same least-specific private label in the DNS, using the following algorithm:
                                 *
                                 * ----- 1. Obtain the list of public DNS suffixes from https://publicsuffix.org/list/effective_tld_names.dat (the client may cache such data), or equivalent functionality as available on the platform.
                                 *
                                 * ----- 2. Extract the host portion of the original AppID URL, before following any redirects.
                                 * 
                                 * ----- 3. The least-specific private label is the portion of the host portion of the AppID URL that matches a public suffix plus one additional label to the left.
                                 * 
                                 * ----- 4. For each Web Origin in the TrustedFacets list, the calculation of the least-specific private label in the DNS must be a case-insensitive match of that of the AppID URL itself. Entries that do not match must be discarded.
                                 */
                                
                                if(tldExists(appID)) {
                                    let facetIDHost = breakURL(facetID).host;
                                    let validIDS    = filterFacets(ids);

                                    if(validIDS.indexOf(facetIDHost) !== -1)
                                        resolve(`Facet is in trusted facet list!`);
                                    else
                                        throw new Error(`Facet ${facetIDHost} is not present in the list of valid trusted facets. ${validIDS}`)
                                }

                                
                            })
                            .catch((error) => reject(error))
                    }

                }

            })
        })


    }


    /**
     * Exporting and stuff
     */
    if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
        module.exports = VerifyFacets;
    } else {
        if (typeof define === 'function' && define.amd) {
            define([], function() {
                return VerifyFacets;
            });
        } else {
            window.VerifyFacets = VerifyFacets;
        }
    }

})()
