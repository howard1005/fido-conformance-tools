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


var getMakeCredentialsChallenge = (formBody) => {
    if(!formBody)
        throw ErrorPromise('Missing "formBody" argument!');

    let serverURL = window.config.test.serverURL;

    /* Remove trailing slash */
    if(serverURL.endsWith('/'))
        serverURL = serverURL.substr(0, serverURL.length - 1);

    return fetch(serverURL + '/attestation/options', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The errorMessage is: ${response.errorMessage}`);

        return response
    })
}

var sendAttestationResponse = (formBody) => {
    if(!formBody)
        throw ErrorPromise('Missing "formBody" argument!');

    let serverURL = window.config.test.serverURL;

    /* Remove trailing slash */
    if(serverURL.endsWith('/'))
        serverURL = serverURL.substr(0, serverURL.length - 1);

    console.info('Sending response to the server: ', formBody)
    return fetch(serverURL + '/attestation/result', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The errorMessage is: ${response.errorMessage}`);

        console.info('Server succeesfully processed the response: ', response)
        return response
    })
}

var getGetAssertionChallenge = (formBody) => {
    if(!formBody)
        throw ErrorPromise('Missing "formBody" argument!');

    let serverURL = window.config.test.serverURL;

    /* Remove trailing slash */
    if(serverURL.endsWith('/'))
        serverURL = serverURL.substr(0, serverURL.length - 1);

    return fetch(serverURL + '/assertion/options', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The errorMessage is: ${response.errorMessage}`);

        return response
    })
}

var sendAssertionResponse = (formBody) => {
    if(!formBody)
        throw ErrorPromise('Missing "formBody" argument!');

    let serverURL = window.config.test.serverURL;

    /* Remove trailing slash */
    if(serverURL.endsWith('/'))
        serverURL = serverURL.substr(0, serverURL.length - 1);

    console.info('Sending response to the server: ', formBody)
    return fetch(serverURL + '/assertion/result', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The errorMessage is: ${response.errorMessage}`);

        console.info('Server succeesfully processed the response: ', response)
        return response
    })
}

var getMDSMetadataForTestCase = (endpoint, testcase) => {
    if(!endpoint || !testcase)
        throw ErrorPromise('Missing "endpoint" or "testcase" argument!');

    return fetch('https://mds.certinfra.fidoalliance.org/getTestMetadata', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({endpoint, testcase})
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The errorMessage is: ${response.errorMessage}`);

        return response.result
    })
}
