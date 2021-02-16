(function() {

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

    let sendRequest = (body, expectedStatusCode, endpointPostfix) => {
        if(type(body) !== 'Object')
            return ErrorPromise('Body must be an Object!')

        let serverURL = window.config.test.serverURL;

        /* Remove trailing slash */
        if(serverURL.endsWith('/'))
            serverURL = serverURL.substr(0, serverURL.length - 1);

        let headers = new Headers({
            /* 3. The client must set the HTTP “Content-Type” header to “application/fido+uaf; charset=utf-8”. [RFC7231] */
            // 'Content-Type': 'application/fido+uaf; charset=utf-8',
            'Content-Type': 'application/json',
            /* 4. The client should include “application/fido+uaf” as a media type in the HTTP “Accept” header. [RFC7231] */
            // 'Accept': 'application/fido+uaf'
        })

        /* 1. The URI of the server endpoint, and how it is communicated to the client, is application-specific. */
        return fetch(serverURL + endpointPostfix, {
            'headers': headers,
            /* 2. The client must set the HTTP method to POST. [RFC7231] */
            'method': 'POST',
            /* 6. The entire POST body must consist entirely of a JSON [ECMA-404] structure described by the GetUAFRequest dictionary. */
            'body': JSON.stringify(body)
        })
        .then((response) => {
            if(response.status === 200)
                return response.json()

            throw new Error(`Server returned error ${response.status}!`)
        })
        .then((response) => {
            if(expectedStatusCode) {
                if(response.statusCode === 1200 || (expectedStatusCode !== 1200 && STATUS_CODES[response.statusCode])) {
                    console.log(`Server responded with expected response code ${response.statusCode}. Message:\n\n\t${STATUS_CODES[response.statusCode]}`)

                    return response
                } else {
                    let errorMessage;
                    if(expectedStatusCode === 1200)
                        errorMessage = `Server returned unexpected status code! Expected ${expectedStatusCode}. Got ${response.statusCode}`;
                    else
                        errorMessage = `Server returned status code that is not listed in the list of valid status codes. Got ${response.statusCode}`;

                    console.error(errorMessage)
                    throw new Error(errorMessage)
                }
            } else
                return response
        })
    }

    let GetUAFRequest = (body, expectedStatusCode, endpointPostfix) => {
        return sendRequest(body, expectedStatusCode, endpointPostfix)
            .then((response) => {

                /* only try to parse message if expected code is success */
                if(expectedStatusCode === 1200) {
                    // TODO: Implement better server response check
                    // let scheme = {
                    //     allOf : [{ 
                    //         '$ref' : 'REST.scheme.json#/definitions/ReturnUAFRequest'
                    //     }]
                    // }

                    // if(!validateDataAgainstScheme(response, scheme).valid) {
                        /**
                         * TODO: improve message
                         */
                    //     console.log(`Invalid ReturnUAFRequest! The message is ${JSON.stringify(response)}`)
                    //     throw new Error(`Invalid ReturnUAFRequest! The message is ${JSON.stringify(response)}`)
                    // }

                    return tryDecodeJSON(response.uafRequest)

                } else
                    return response

            })
    }

    let SentUAFResponse = (body, expectedStatusCode, endpointPostfix) => {
        return sendRequest(body, expectedStatusCode, endpointPostfix)
            .then((response) => {
                // TODO: Implement better server response check
                // let scheme = {
                //     allOf : [{ 
                //         '$ref' : 'REST.scheme.json#/definitions/ServerResponse'
                //     }]
                // }

                // if(!validateDataAgainstScheme(response, scheme).valid) {
                //     /**
                //      * TODO: improve message
                //      */
                //     throw new Error(`Invalid ServerResponse! The message is ${JSON.stringify(response)}`)
                // }

                return response

            })
    }

    var rest = {
        register : {
            get : (expectedStatusCode, username) => {
                let body = {
                    'op' : 'Reg',
                    'context' : JSON.stringify({
                        'username' : username || 'FIDOnotTheDogAlliance'
                    })
                }

                return GetUAFRequest(body, expectedStatusCode, '/get')
            },
            post : (uafProtocolMessage, expectedStatusCode) => {
                let body = {
                    'uafResponse' : uafProtocolMessage
                }

                return SentUAFResponse(body, expectedStatusCode, '/respond')
            }
        },
        
        authenticate : {
            get  : (expectedStatusCode, username, transaction) => {
                let body = {
                    'op' : 'Auth',
                    'context' : JSON.stringify({
                        'username' : username || 'FIDOnotTheDogAlliance',
                        'transaction' : transaction
                    })
                }

                return GetUAFRequest(body, expectedStatusCode, '/get')
            },
            post : (uafProtocolMessage, expectedStatusCode, username) => {
                let body = {
                    'uafResponse' : uafProtocolMessage
                }

                return SentUAFResponse(body, expectedStatusCode, '/respond')
            }
        },

        deregister : {
            get  : (expectedStatusCode, username, options) => {
                let context = {
                    'deregisterAAID': undefined,
                    'deregisterAll': undefined,
                    'username' : username || 'FIDOnotTheDogAlliance'
                }

                if(options && options.deregisterAAID)
                    context.deregisterAAID = options.deregisterAAID;

                if(options && options.deregisterAll)
                    context.deregisterAll = options.deregisterAll;

                let body = {
                    'op' : 'Dereg',
                    'context' : JSON.stringify(context)
                }

                return GetUAFRequest(body, expectedStatusCode, '/get')
            }
        }
    }

    window.rest = rest;
})()
