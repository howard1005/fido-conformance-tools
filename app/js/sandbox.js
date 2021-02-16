(function() {
    let executeCodeInSandbox = function(sourceCode, global) {
        function has(target, key) {  
            return true
        }

        function get(target, key) {

            if (key === 'navigator') {
                return target.window.navigator
            }

            if(type(target[key]) === 'Function')
                if(isNative(target[key]))
                    target[key] = target[key].bind(window)

            if (key === Symbol.unscopables) 
                return undefined

            return target[key] || target.window[key];
        }

        function compileCode (src) {  
            src = 'with (sandbox) {' + src + '}'
            const code = new Function('sandbox', src)
            return function (scope) {
                /* Creating object proxy */
                const sandboxProxy = new Proxy(scope, {has, get});
                code(sandboxProxy);
            }
        }

        let compiler = compileCode(sourceCode);

        compiler(global);
    }

    /**
     * Object cloning function
     */
    let clone = function(obj) {
        if (null == obj || "object" != typeof obj) 
            return obj

        let copy = {};
        for (let attr in obj)
            if (obj.hasOwnProperty(attr))
                copy[attr] = obj[attr];

        return copy
    }

    /**
     * Single run test execution sandbox environment
     */
    let sandbox = new function() {
        /* helpers and tests array */
        let helpers = [];
        let tests   = [];

        let exec = () => {
            let w = clone(window);
            w.navigator = {};
            

            if(window.currentPlatform !== 'browser') {
                if(window.config.test.serverURL) {
                    let brokenURL = breakURL(window.config.test.serverURL);
                    w.location = {
                        'href': window.config.test.serverURL,
                        'ancestorOrigins': {},
                        'origin': brokenURL.origin,
                        'protocol': brokenURL.protocol,
                        'host': brokenURL.host,
                        'hostname': brokenURL.host,
                        'port': brokenURL.port,
                        'pathname': '/',
                        'search': '',
                        'hash': ''
                    }
                } else {
                    w.location = {
                        'href': 'https://uaf.example.com/',
                        'ancestorOrigins': {},
                        'origin': 'https://uaf.example.com',
                        'protocol': 'https:',
                        'host': 'uaf.example.com',
                        'hostname': 'uaf.example.com',
                        'port': '',
                        'pathname': '/',
                        'search': '',
                        'hash': ''
                    }
                }

                w.window.location = w.location;
            }


            return runTests(w)
        }

        let reset = () => {
            helpers = [];
            tests = [];
        }
        
        let load = {
            'helper': (script) => {
                if(helpers.indexOf(script) === -1)
                    helpers.push(script);
            },

            'test': (script) => {
                if(tests.indexOf(script) === -1)
                    tests.push(script);
            }
        }

        var runTests = function(window) {
            // https://stackoverflow.com/questions/28337702/how-to-clear-mocha-js-state-in-browser
            mocha.suite.suites = [];
            mocha.suite._bail  = false;

            let helperPromises = helpers.map((helper) => {
                return fetch(`${window.config.baseURL}${helper}`)
                            .then((response) => response.text())
            });

            let testPromises = tests.map((test) => {
                return fetch(`${window.config.baseURL}${test}`)
                            .then((response) => response.text())
            });

            return Promise.all([
                Promise.all(helperPromises),
                Promise.all(testPromises)
            ])
            .then(function(results) {
                let sourceCode = '';

                let testHelpers = results[0]
                let testCases   = results[1]

                /**
                 * Loading helpers
                 */
                for(let script of testHelpers)
                    sourceCode += `${script};\n\n`;

                /**
                 * Loading vendor helpers
                 */
                for(let key in window.config.test.helpers) {
                    let helper = window.config.test.helpers[key];

                    if(helper.active) {
                        let source = atob(helper.data);

                        sourceCode += `${source};\n\n`;
                    }
                }

                /**
                 * Loading tests
                 */
                for(let script of testCases)
                    sourceCode += `${script};\n\n`;

                return sourceCode

            })
            .then((sourceCode) => {
                executeCodeInSandbox(sourceCode, window)
            })
        }
        
        return {
            load,
            exec, 
            reset
        }
    }

    window.sandbox = sandbox;
})()