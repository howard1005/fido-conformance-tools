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

if(!window.config)
    window.config = {};

if(!window.scriptsRoot || window.scriptsRoot === '')
    window.config.root = window.location.href
                                .match(/(.+)?\//gmi)[0];
else
    window.config.root = scriptsRoot;

/**
 * Simple localstorage config database
 * @type {Object}
 */
var db = {
    'save': (data, key) => {
        let k = key || 'config';
        let d = JSON.stringify(data)
        localStorage.setItem(k, d);
    },

    'get': (key) => {
        let k = key || 'config';
        return JSON.parse(localStorage.getItem(k)) || {};
    }
};

/**
 * Appends script with given URL to the body
 * @param  {String} url - URL of the script
 */
let loadScript = (url) => {
    return new Promise((resolve, reject) => {
        console.log('Adding new script... ', url);
        let scriptNode = document.createElement('script');
        scriptNode.src = `${window.config.baseURL}${url}`;

        scriptNode.onload = function() {
            resolve('All done!');
        };

        scriptNode.onerror = function(error){
            reject(error);
        };

        document.head.appendChild(scriptNode);
    })
}

/**
 * Loads json schemes into AJV
 * @param  {Array} schemes
 * @return {Promise}       - Schemes load completion promise
 */
let loadSchemes = (schemes) => {
    window.ajv = new Ajv();

    let promises = [];
    let getScheme = (scheme) => {
        return fetch(`${window.config.baseURL}schemes/${scheme}`)
            .then((response) => {
                /**
                 * Appending template URL as ID
                 */
                return response.json()
                    .then((data) => {
                        data.id = response.url;
                        return data
                    })
            })
    }

    for(let scheme of schemes)
        promises.push(getScheme(scheme));

    return Promise.all(promises)
        .then((schemes) => {
            for(let scheme of schemes)
                ajv.compile(scheme)
        })
}

/**
 * Loads authenticator metadata statemets
 * @param  {Array} schemes
 * @return {Promise}       - Schemes load completion promise
 */
let loadMetadataStatements = (statements) => {
    if (statements) {
        let getMDS = (statement) => {
             return fetch(`${window.config.baseURL}metadata/${encodeURIComponent(statement)}`)
                .then((response) => response.json())
        }

        let fetchPromises = [];
        for(let statement of statements)
            fetchPromises.push(getMDS(statement));

        return Promise.all(fetchPromises)
            .then((metadataStatements) => {
                let statements = {};

                for(let statement of metadataStatements)
                    statements[statement.aaid || statement.description] = statement;

                config.manifesto.metadataStatements = statements;
            })
    } else
        return Promise.resolve();
}

let loadMetainformation = () => {
    let manifestos = [];
    for(let testSuit of window.config.availableSuits) {
        let p = fetch(`${window.config.root}../modules/${testSuit}/manifesto.json`)
            .then((response) => response.json())
            .then((response) => {
                response.id = testSuit;

                return response
            })

        manifestos.push(p);
    }

    return Promise.all(manifestos);
}

/**
 * Loads test suit
 * @param  {String} testSuit - test suit
 * @return {Promise}         - loading promise
 */
let loadTestSuit = (testSuit) => {
    if(window.config.availableSuits.indexOf(testSuit) === -1)
        throw new Error(`Testsuit "${testSuit}" is unavailable!`);

    let baseURL = `${window.config.root}../modules/${testSuit}/`;
    window.config.baseURL = baseURL;

    return fetch(`${window.config.baseURL}manifesto.json`)
        .then((result) => result.json())

        /* ----- Load Manifesto ----- */
        .then((result) => {
            // Set manifesto
            window.config.manifesto = result;

            // Set default fields
            window.config.test = Object.assign({}, result.defaults);

            // Create test cases array
            window.config.testCases = [];

            return Promise.all([
                loadSchemes(window.config.manifesto.schemes),
                loadMetadataStatements(window.config.manifesto.availableMetadataStatements)
            ])
        })

        /* ----- Load available test lists ----- */
        .then(() => {
            let promises = []
            for (let key in window.config.manifesto.testLists) {
                console.log('Loading key... ', key)
                if(window.config.manifesto.testLists[key]){
                    let p = fetch(`${window.config.baseURL}${window.config.manifesto.testLists[key]}`)
                        .then((response) => response.json())
                        .then((response) => {
                            window.config.manifesto.testLists[key] = response;
                        })

                    promises.push(p);
                }
            }

            return Promise.all(promises)
        })
        .then(() => {
            let backup = db.get();

            for(let key in backup) {
                if(type(backup[key]) !== 'Object')
                    window.config[key] = backup[key]
                else {
                    if(!window.config[key])
                        window.config[key] = {};

                    for(let subKey in backup[key])
                        if(!window.config[key][subKey])
                            window.config[key][subKey] = backup[key][subKey];
                }
            }
        })
        .catch((err) => new Error(`Error while loading test suit:\n ${err}`))
}


/**
 * Loads test lists
 * @param  {String} testList - name of the testList
 * @param  {String} testCases - name of the specific list of cases (OPTIONAL)
 * @return {Promise}
 */
let loadTestList = (testList, testCases) => {
    if(!window.config.manifesto.testLists[testList])
        throw new Error(`TestList "${testList}" is unavailable!`);

    if(testCases) {
        for(let tc of testCases)
            if(!window.config.manifesto.testLists[testList].tests[tc])
                throw new Error(`Test case "${testCases[tc]}" is does not exist!`);
    }

    sandbox.reset();

    let tests = [];
    if(testCases)
        for(let tc of testCases)
            tests.push(window.config.manifesto.testLists[testList].tests[tc]);
    else
        tests = window.config.manifesto.testLists[testList].tests;

    for(let key in tests) {
        let cases = [];
        let test = tests[key];

        for(let dep of window.config.manifesto.dependencies)
            sandbox.load.helper(dep);

        if(window.config.manifesto.setup)
             sandbox.load.helper(window.config.manifesto.setup);

        for(let helper of test.helpers)
            sandbox.load.helper(helper);

        for(let testCase of test.cases)
            sandbox.load.test(testCase)
    }

    return sandbox.exec();
}
