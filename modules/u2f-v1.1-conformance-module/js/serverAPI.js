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

var getRegister = (formBody) => {
    if(!formBody)
        throw ErrorPromise('Missing "formBody" argument!');

    let serverURL = window.config.test.serverURL;

    /* Remove trailing slash */
    if(serverURL.endsWith('/'))
        serverURL = serverURL.substr(0, serverURL.length - 1);

    return fetch(serverURL + '/register/get', {
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

var registerResponse = (formBody) => {
    if(!formBody)
        throw ErrorPromise('Missing "formBody" argument!');

    let serverURL = window.config.test.serverURL;

    /* Remove trailing slash */
    if(serverURL.endsWith('/'))
        serverURL = serverURL.substr(0, serverURL.length - 1);

    return fetch(serverURL + '/register/response', {
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

var getSign = (formBody) => {
    if(!formBody)
        throw ErrorPromise('Missing "formBody" argument!');

    let serverURL = window.config.test.serverURL;

    /* Remove trailing slash */
    if(serverURL.endsWith('/'))
        serverURL = serverURL.substr(0, serverURL.length - 1);

    return fetch(serverURL + '/sign/get', {
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

var signResponse = (formBody) => {
    if(!formBody)
        throw ErrorPromise('Missing "formBody" argument!');

    let serverURL = window.config.test.serverURL;

    /* Remove trailing slash */
    if(serverURL.endsWith('/'))
        serverURL = serverURL.substr(0, serverURL.length - 1);

    return fetch(serverURL + '/sign/response', {
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
