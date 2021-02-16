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

/**
 * @param  {String}  - Test id
 * @return {Promise} - Promise
 */
var getTestStaticJSON = (testId, options) => {
    let regex = /^((\w+-)+\d{0,2}-F-\d{0,2})$/;

    if(regex.test(testId))
        testId = testId + '-1';

    return fetch(`${config.baseURL}static_json_responses/${testId}.test.json`)
        .then((response) => response.json())
        .then((response) => {
            return new Promise((resolve, reject) => {
                if(!options || (typeof options.applyPolicy === 'boolean' && options.applyPolicy)) {
                    /**
                     * Applying policy
                     */
                    try {
                        response[0].policy.accepted.push([{'aaid': [config.test.metadataStatement.aaid]}])
                    } catch(e) {}
                }

                if(!options || !options.dontModifyAppID) {
                    /**
                     * Applying correct appID
                     */
                    try {
                        if(options && options.appID)
                            response[0].header.appID = options.appID;
                        else
                            response[0].header.appID = '';

                    } catch(e) {}
                }

                /**
                 * Slows down testing process to help with concurrency to various implementations
                 */
                setTimeout(() => {
                    resolve(response)
                }, 150)
            })
        })
}

/**
 * Retrieves authToken for the given facetID
 * @param  {String} facetID  - iOS or Android facet
 * @return {Promise<String>} - authToken
 */
var getFacetAndAppIDAuthToken = (facetID) => {
    let facetIDRegex = /^(android:apk-key-hash:([-A-Za-z0-9+\/=]|=[^=]|={3,})+)|(ios:bundle-id:\w+(\.\w+)+)$/;
    
    if(!facetIDRegex.test(facetID) && window.currentPlatform !== 'electron')
        return Promise.reject(new Error('Invalid facetID format! For Android it MUST be android:apk-key-hash:<sha1_hash-of-apk-signing-cert> and for iOS ios:bundle-id:<ios-bundle-id-of-app>!'))

    return window.fetch('https://appid.certinfra.fidoalliance.org/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body: `facetID=${facetID}`
    })
    .then((response) => response.json())
    .then((response) => response.authToken)
    .catch((errorMessage) => {
        throw new Error(`Error while fetching AuthToken. Mesage is: ${errorMessage}`)
    })
}

/**
 * Retrieves appID of the test for the given authToken
 * @param  {String} authToken
 * @param  {String} testName
 * @return {Promise<String>} - AppID
 */
var getFacetAndAppIDTestURL = (authToken, testName) => {
    return window.fetch('https://appid.certinfra.fidoalliance.org/get', {
        method: 'POST',
        headers: {
            'Authorization': authToken,
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body: `testName=${testName}`
    })
    .then((response) => response.json())
    .then((response) => response.appID)
}

/**
 * Sets appID test case
 * @param  {String} appID
 * @param  {String} testName
 * @return {Promise}
 */
var setAppIDTestCase = (appID, testName) => {
    return window.fetch('https://appid.certinfra.fidoalliance.org/set', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body: `appID=${encodeURIComponent(appID)}&testName=${testName}`
    })
}

/**
 * Authenticator processUAFOperation helper.
 * It expects that authenticator.processUAFOperation will call errorCallback.
 * @param  {UAFMessage} UAFMessage - UAF Message
 * @return {Promise}
 */
var expectProcessUAFOperationFail = (UAFMessage) => {
    return new Promise(function(resolve, reject) {
        authenticator.processUAFOperation(UAFMessage)

        /**
         * completionCallback
         */
        .then((response) => reject('Client succeeded when expected fail.'))

        /**
         * errorCallback
         */
        .catch((error) => resolve(error));
    })
}

/**
 * Authenticator processUAFOperation helper.
 * It expects that authenticator.processUAFOperation will call completionCallback.
 * @param  {UAFMessage} UAFMessage - UAF Message
 * @return {Promise}
 */
var expectProcessUAFOperationSucceed = (UAFMessage) => {
    return authenticator.processUAFOperation(UAFMessage)
}

/**
 * Takes promise, and inverses it. So it rejects if succeeds, and resolve if fails
 * @param  {Promise} promise
 * @return {Promise}
 */
var expectPromiseToFail = (promise) => {
    return new Promise((resolve, reject) => {
        promise
            .then((success) => reject(success))
            .catch((fail)   => resolve(fail))
    })
} 

/**
 * Generates new authenticator, and wraps processUAFOperation in a Promise
 * @param  {String} facetID - facetId
 * @param  {String} aaid    - aaid of an authenticator
 * @return {Object}         - methods
 */
var getNewAuthenticator = (facetID, aaid, modifierParams) => {
    let authr = new window.UAF.UAFClientAPI(facetID, {
        'aaid': aaid,
        'metadataStatement': window.config.manifesto.metadataStatements[aaid],
        'selectKeyHandleCallback': (users, sucessCallback, failCallback) => {
            sucessCallback(users[0])
        },
        'confirmTransactionContentCallback': (transaction, successCallback, failCallback) => {
            successCallback()
        }
    }, modifierParams)


    return {
        'processUAFOperation' : (uafMessage) => {
            return new Promise((resolve, reject) => {
                authr.processUAFOperation(uafMessage, 
                    (success) => resolve(success),
                    (error)   => reject(error))
            })
        }
    }
}


let protocolVersion = {
    'major': 1,
    'minor': 1
}

/**
 * Takes UPV object and verifies that it's matches current version of protocol
 * @param  {Object}  versionObject
 * @return {Boolean}
 */
var verifyProtocolVersion = (versionObject) => versionObject.major === protocolVersion.major && versionObject.minor === protocolVersion.minor;

/**
 * Promise reflect function
 * 
 * https://stackoverflow.com/questions/31424561/wait-until-all-es6-promises-complete-even-rejected-promises
 * 
 * @param  {Promise}
 * @return {Promise}
 */
var reflectPromise = function(promise) {
    return promise.then(function(v){ return {v:v, status: 'resolved' }},
                        function(e){ return {e:e, status: 'rejected' }});
}

/**
 * Generates a random FinalChallenge
 * @return {String} - Base64URL encoded final challenge
 */
var generateRandomFinalChallenge = () => {
    let struct = {
        'appID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg=',
        'challenge': generateRandomString(42),
        'channelBinding': {},
        'facetID': 'android:apk-key-hash:LK84ci82ruA6u8SyF26cghsVwZg='
    }

    return stringToBase64URL(JSON.stringify(struct))
}
