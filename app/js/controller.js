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
     * Modal tiny fix tha makes your like better
     */
    var modal = (selector) => {
        let div = $(selector)[0];

        if(!div.showModal)
            dialogPolyfill.registerDialog(div);

        return div;
    }

    var toaster = (message) => {
        $('.mdl-snackbar')[0].MaterialSnackbar.showSnackbar({
            message: message
        });
    }

    let supportedPlatforms = window.electronSupportedPlatforms || ['browser'];
    window.currentPlatform = window.currentPlatform || 'browser';
    let ids = {
        'mochaResetBtn': '.fido__test__mocha--reset',
        'mochaStartBtn': '.fido__test__mocha--start',
        'mochaStopBtn': '.fido__test__mocha--stop',
        'mochaDiv': '.mocha',
        'checkBoxes': '.fido__testlist__item',
        'testSelect': '.fido__test__selector--container',
        'testConfig': '.fido__test__configuration--container',
        'testListOptions': '.fido__testlist__item.fido__testlist__option',
        'testCaseOptions': '.fido__testlist__item.fido__testcase__option',
        'testConfigOption': '.fido__config__option',
        'testList': '.fido__testlist',

        'filePromtHelpers': '.fido__test__helpers--promt',
        'fileDropHelpers': '.fido__test__helpers--drop__zone',
        'fileListHelpers': '.fido__test__helpers--file_list',

        'filePromtMetadata': '.fido__test__metadata--promt',
        'fileDropMetadata': '.fido__test__metadata--drop__zone',
        'authenticatorInfo': '.fido__authenticator_info',
        'authenticatorInfoContainer': '.fido__authenticator_info--container',
        'buttonClearAuthenticatorInfo': '.fido__authenticator_info--clear',

        'downloadMetadataButton': '.fido__metadata--download',

        'helpers': '.fido__test__helpers--file_list',
        'helperSwitch': '.fido__test__helpers--switch',
        'helperDelete': '.fido__test__helpers--delete',
        'suitBtn': '.fido__test__suit__select--button',
        'staticSuitBtn': '.fido__test__suit__static--button',
        'backToMainMenu': '.fido__test__selector__page',
        'resetDivs': '.fido__empty__onreset',
        'hideDivs': '.fido__hide__onreset',
        'subTitle': '.fido__subtitle',
        'confirmDialog': 'dialog.fido__confirm__dialog',
        'confirmTrue': '.fido__confirm__dialog--confirm',
        'confirmFalse': '.fido__confirm__dialog--cancel',

        'submitResultsButton': '.fido__results__submit--button',
        'submitResultsModal': '.fido__results__submit--modal',
        'submitResultsForm': '#fido__results__submit--form',
        'submitResultsFormSubmit': '.fido__results__submit--confirm',
        'submitResultsFormCancel': '.fido__results__submit--cancel',
        'submitResultsProductName': '.fido__results__submit--ProductName',
        'submitResultsGUID': '.fido__results__submit--CompanyName',
        'submitResultsGUID': '.fido__results__submit--Email',

        'advancedConfigModal': '.fido__tool__advanced__config--modal',

        'openInspector': '.fido__dialog--open-inspector',
        'openToolsInBrowser': '.fido__dialog--open-tools-in-the-browser',
        'resetConfig': '.fido__dialog--reset-config',
        'dialogControls': '.fido__dialog--button',
        'dialogClose': '.fido__dialog__controls--close',

        'advancedConfig': '.fido__dialog--advanced-config',
        'advancedConfigForm': '#fido__tool__advanced__config--form',
        'advancedConfigFormCancel': '.fido__tool__advanced__config--cancel',
        'advancedConfigFormHIDPSize': '.fido__tool__advanced__config--hidpacketsize',
        'advancedConfigFormMinRSSI': '.fido__tool__advanced__config--minrssi',
        'advancedConfigFormBleGracePeriod': '.fido__tool__advanced__config--blegraceperiod',

        'FIDOAuthrList': '.fido__fidoauthenticators_list',
        'FIDOAuthr': '.fido__fidoauthenticators__authr',
        'FIDOAuthrOption': '.fido__fidoauthenticators__authr-option',

        'eulaModal': '.fido__eula--modal',
        'DeclineEULA': '.fido__dialog__controls--decline-eula',
        'AcceptEULA': '.fido__dialog__controls--accept-eula'
    }

    /**
     * Return to main menu
     */
    $(ids['confirmTrue']).click((e) => {
        $('.fido__test__container')
            .hide();
        $('.fido__test__controls')
            .hide();
        $(ids['backToMainMenu'])
            .hide();
        $('.fido__test__suit__select--container')
            .parent()
            .show();

        $(ids['resetDivs'])
            .empty();

        $(ids['hideDivs'])
            .hide();

        resetTestConfig();

        modal(ids['confirmDialog']).close();
    });

    $(ids['confirmFalse']).click((e) => {
        modal(ids['confirmDialog']).close();
    });

    /**
     * Return to main menu
     */
    $(ids['backToMainMenu']).click(() => {
        modal(ids['confirmDialog']).showModal()
    })

    $(ids['openInspector']).click(() => {
        window.openInspector();
    })

    $(ids['openToolsInBrowser']).click(() => {
        window.openToolsInBrowser();
    })

    $(ids['resetConfig']).click(() => {
        if(confirm('Are you sure you want to reset tool config?!')) {
            db.save('{}', 'config');
            window.forceReloadPage();
        }
    })

    $(ids['advancedConfig']).click(() => {
        if(confirm('CHANGING DEFAULT TOOL CONFIG MAY RESULT IN UNEXPECTED BEHAVIOUR! ARE YOU SURE YOU WANT TO DO THAT?')) {
            $(ids['advancedConfigFormHIDPSize']).val(window.config.test.CustomHIDConfigSize);
            $(ids['advancedConfigFormMinRSSI']).val(window.config.test.CustomBLERSSI);
            $(ids['advancedConfigFormBleGracePeriod']).val(window.config.test.CustomBLEGracePeriod);
            modal(ids['advancedConfigModal']).showModal()
        }
    })


    $(ids['advancedConfigFormCancel']).click(() => {
        modal(ids['advancedConfigModal']).close()
    })

    $(ids['advancedConfigForm']).submit(function(){
        if(!window.config)
            window.config = {};

        if(!window.config.test)
            window.config.test = {};

        if(hidpacketsize.value) {
            delete window.config.test.CustomHIDConfigSize;
            window.config.test.CustomHIDConfigSize = parseInt(hidpacketsize.value);
            navigator.fido.fido2.hid.setCustomPacketSize(window.config.test.CustomHIDConfigSize);
        }

        if(minrssi.value) {
            delete window.config.test.CustomBLERSSI;
            window.config.test.CustomBLERSSI = parseInt(minrssi.value);
            navigator.fido.fido2.ble.setMinRSSI(window.config.test.CustomBLERSSI);
        }

        if(blegraceperiod.value) {
            delete window.config.test.CustomBLEGracePeriod;
            window.config.test.CustomBLEGracePeriod = parseInt(blegraceperiod.value);
            navigator.fido.fido2.ble.setMinRSSI(window.config.test.CustomBLEGracePeriod);
        }

        modal(ids['advancedConfigModal']).close()
    })


    /* ----- EULA ----- */

    window.checkEULA = () => {
        if(!localStorage["eula"])
            modal(ids["eulaModal"]).showModal()
    }

    $(ids['DeclineEULA']).click((e) => {
        window.quitApp();
    });

    $(ids['AcceptEULA']).click((e) => {
        localStorage["eula"] = true
    });

    /* ----- Dialog controlls ----- */
        $(document).on('click', ids['dialogControls'], function() {
            let dialogSelector = $(this).data('for');

            if($(dialogSelector).length)
                modal(dialogSelector).showModal();
        })


        $(document).on('click', ids['dialogClose'], function() {
            let parentDialogs = $(this).closest('dialog');

            if(parentDialogs.length)
                parentDialogs[0].close();
        })
    /* ----- Dialog controlls end ----- */

    /**
     * Suit button
     */
    var loadTestSuitHtml = (testSuit) => {
        loadTestSuit(testSuit)
            .then(() => {
                config.manifesto.testLists = filterTestLists(config.manifesto.testLists);
                $('.fido__test__container')
                    .show();
                $('.fido__test__controls')
                    .show();
                $(ids['backToMainMenu'])
                    .show();
                $('.fido__test__suit__select--container')
                    .parent()
                    .hide();

                $(ids['subTitle'])
                    .text(`(${config.manifesto.name}${config.manifesto.protocolVersion !== "" ? " " + config.manifesto.protocolVersion : ""})`)

                $(ids['testSelect'])
                    .append(render.testLists(config.manifesto.testLists));
                $(ids['testConfig'])
                    .append(render.configOptions(getRequiredFields()));
                $(ids['fileListHelpers'])
                    .append(render.helpers(config.test.helpers))

                showAuthenticatorInfo(config.test.metadataStatement)

                window.config.ready = true;
                window.config.testSuit = testSuit;
            })
    }

    /**
     * Generate list of required fields
     */
    let getRequiredFields = () => {
        let requiredFields = [];
        for(let testlistID in config.manifesto.testLists) {
            let testList = config.manifesto.testLists[testlistID];

            if(arrayContainsItem(supportedPlatforms, testList.platform)) {
                if(testList.required.all)
                    requiredFields = requiredFields.concat(testList.required.all);

                for(let platform of supportedPlatforms) {
                    if(testList.required[platform])
                        requiredFields = requiredFields.concat(testList.required[platform]);
                }
            }
        }

        return requiredFields;
    }

    let filterTestLists = (testLists) => {
        let filteredTestLists = {};
        for(let testlistID in testLists) {
            let testList = testLists[testlistID];

            if(arrayContainsItem(supportedPlatforms, testList.platform)) {
                let filteredTestCases = {};

                for(let testCaseID in testList.tests) {
                    if(!testList.tests[testCaseID].platform
                    || arrayContainsItem(supportedPlatforms, testList.tests[testCaseID].platform)) {
                        filteredTestCases[testCaseID] = testList.tests[testCaseID];
                    }
                }

                testList.tests = filteredTestCases;

                filteredTestLists[testlistID] = testList;
            }
        }

        return filteredTestLists;
    }

    $(document).on('click', ids['suitBtn'], function() {
        let testSuit = $(this).data('id');
        loadTestSuitHtml(testSuit);
    })

    let passedTests = [];
    let failedTests = [];

    let allTestsAreSelected = () => {
        for(let test in config.manifesto.testLists[config.testList].tests) {
            if(config.testCases.indexOf(test) === -1)
                return false
        }

        return true
    }


    let matchesRequirements = () => {
        if(!window.config.testCases.length) {
            alert('No test cases selected')
            return false
        }

        let testList = window.config.manifesto.testLists[window.config.testList];

        if(!testList) {
            alert('Invalid test list id!');
            console.log('window.config.testList is not a memeber of the window.config.manifesto.testLists!');
            return false
        }

        let requiredFields = [];

        requiredFields = requiredFields.concat(testList.required.all);
        for(let platform of supportedPlatforms) {
            if(testList.required[platform]) {
                requiredFields = requiredFields.concat(testList.required[platform]);
            }
        }

        for(let field of requiredFields) {
            if(!window.config.test[field]) {
                alert(`Missing ${field} field. Please fill all of the required fields!`);
                return false
            }
        }

        return true
    }

    let testsAreRunning = false;
    /**
     * Start button
     */
    $(ids['mochaStartBtn']).click((event) => {
        event.preventDefault();

        if(!matchesRequirements())
            return

        $(ids['mochaStartBtn']).hide();

        loadTestList(window.config.testList, window.config.testCases)
            .then(() => {
                window.config.runner = mocha.run();
                // engageAutoScroll();
                testsAreRunning = true;
                passedTests = [];
                failedTests = [];

                $(ids['submitResultsButton']).hide();


                window.config.runner
                    .on('test', (test) => {
                        console.log('Test started: ' + test.title);
                    })
                    .on('pass', (test) => {
                        passedTests.push(test);
                    })
                    .on('fail', (test) => {
                        failedTests.push(test);
                    })
                    .on('end', () => {
                        testsAreRunning = false;
                        if(!failedTests.length) {
                            if(allTestsAreSelected())
                                $(ids['submitResultsButton']).show();
                        }
                    });
            })
            .catch((error) => {
                console.log(`Error while executing tests. Error message: ${error}`);
                alert(`Error while executing tests. Error message: ${error}`);
            })
    })



    /* ----- Submit results ----- */


    $(ids['submitResultsButton']).click((e) => {
        $(ids['submitResultsProductName']).val('');
        $(ids['submitResultsGUID']).val('');

        modal(ids['submitResultsModal']).showModal();
    });

    $(ids['submitResultsFormCancel']).click((e) => {
        modal(ids['submitResultsModal']).close();
    });

    $(ids['submitResultsFormSubmit']).click((e) => {
        $(ids['submitResultsForm']).submit();
    });

    $(ids['submitResultsForm']).submit(function(e) {
        e.preventDefault();

        if(!this.CompanyName.value 
        || !this.ProductName.value
        || !this.Email.value) {
            toaster('You must fill all of the fields!')
            return
        }

        modal(ids['submitResultsModal']).close();

        submitResults({
            'product_name': this.ProductName.value,
            'company_name': this.CompanyName.value,
            'email': this.Email.value
        })
        .then(() => {
            toaster('Successfully submitted results!')
        })
        .catch((error) => {
            console.log(error);
            toaster('Error while submitting results!')
        })
        
    })

    let submitResults = (info) => {
        let errorJSON = (err) => {
            let res = {};

            Object.getOwnPropertyNames(err).forEach(function (key) {
                res[key] = err[key];
            }, err);

            return res;
        }

        let clean = (test) => {
            return {
                title: test.title,
                fullTitle: test.fullTitle(),
                duration: test.duration,
                currentRetry: test.currentRetry(),
                err: errorJSON(test.err || {})
            };
        }

        info.protocol_family = config.manifesto.name;
        info.protocol_version = config.manifesto.protocolVersion;
        info.tool_version = packageVersion;
        info.passed = passedTests.map(clean).length;
        info.implementation_class = config.testList;
        info.platform = window.currentPlatform;
        info.meta = {};

        for(let key of getRequiredFields())
            info.meta[key] = config.test[key];

        info.meta = JSON.stringify(info.meta);
        
        return fetch('https://results.certinfra.fidoalliance.org/submit', {
            'method': 'post',
            'body': JSON.stringify(info),
            'headers': {
              'Content-Type': 'application/json',
              'Accept': 'applicatison/json'
            }
        })
    }

    /**
     * Stop button
     */
    $(ids['mochaStopBtn']).click((event) => {
        event.preventDefault();

        if (window.config.runner) {
            // https://stackoverflow.com/questions/28337702/how-to-clear-mocha-js-state-in-browser
            mocha.suite.suites = [];
            mocha.suite._bail  = false;

            window.config.runner.suite.bail(true);
            window.config.runner.uncaught(Error("FORCED TERMINATION"));
        }
    })

    /**
     * Restart button
     */
    $(ids['mochaResetBtn']).click((event) => {
        event.preventDefault();
        /**
         * TODO: Temp DEBUG
         */
        forceReloadPage();
        $(ids['mochaStopBtn']).click();
        $(ids['mochaDiv']).empty();
    })

    /**
     * Select all test cases
     */
    $(document).on('change', ids['testListOptions'], function() {
        let childButtons = $(this.closest(ids['testList'])).find(ids['testCaseOptions']);
        let Super = this;

        $(ids['checkBoxes']).each(function() {
            if(Super !== this)
                $(this).prop('checked', false);
        })

        childButtons.each(function() {
            $(this).prop('checked', false); })

        if(this.checked) {
            window.config.testList = $(this).data('key');
            childButtons.each(function(){
                $(this).click(); })
        } else {
            window.config.testList  = '';
            window.config.testCases = [];
        }
    });

    /**
     * Test case selection
     */
    $(document).on('change', ids['testCaseOptions'], function() {
        let key     = $(this).data('key');
        let checked = $(this).prop('checked');
        let index   = window.config.testCases.indexOf(key);
        let parent  = $(this.closest(ids['testList'])).find(ids['testListOptions']);

        if(!parent.prop('checked')) {
            $(ids['testCaseOptions'])
                .prop('checked', false)

            $(ids['testListOptions'])
                .prop('checked', false)

            parent
                .prop('checked', true)
            $(this)
                .prop('checked', true)

            window.config.testList = parent.data('key');
            window.config.testCases = [];
        }

        if(!checked && index !== -1)
            window.config.testCases.splice(index, 1);

        if(checked && index === -1)
            window.config.testCases.push(key);
    })

    /**
     * Test config option change handler
     */
    $(document).on('change', ids['testConfigOption'], function() {
        let key    = $(this).data('key');
        let parent = $(this).data('parent');
        let value  = this.value;

        if(parent === undefined || parent === '' || parent === 'undefined')
            window.config.test[key] = value;
        else {
            if(!window.config.test[parent])
                window.config.test[parent] = {};

            if($(this).attr('type') === 'checkbox')
                window.config.test[parent][key] = $(this).prop('checked');
            else
                window.config.test[parent][key] = value;
        }

    })

    let saveTestConfig = () => {
        db.save({
            'testSuit': window.config.testSuit,
            'testCases': window.config.testCases,
            'testList': window.config.testList,
            'test': window.config.test
        })
    }

    let resetTestConfig = () => {
        window.config.testSuit  = undefined;
        window.config.testList  = undefined;
        window.config.testCases = undefined;
        window.config.test      = undefined;
        window.config.ready     = false;

        saveTestConfig();
    }


    /**
     * Watch changes to the config, and save config if change appears
     */
    watch(window.config, ['testSuit', 'testCases', 'testList', 'test'], function(prop, action, newvalue){
        console.log('Detected changes')

        if(window.config.ready) {
            if(prop === 'helpers' 
            || (newvalue && newvalue.added
            && arrayContainsItem(newvalue.added, 'helpers')))
                $(ids['fileListHelpers'])
                .empty()
                .append(render.helpers(config.test.helpers));

            saveTestConfig();
        }

        console.log('Saved changes')

    }, 7, true);



    /* ----- Download metadata ----- */
    $(document).on('click', ids['downloadMetadataButton'], function() {
        let zip = new JSZip();

        let mdsFolder = zip.folder('metadataStatements');

        for(let aaid in window.config.manifesto.metadataStatements) {
            let mds = window.config.manifesto.metadataStatements[aaid];
            mdsFolder.file(`${aaid}.json`, JSON.stringify(mds, null, 4))
        }

        zip.generateAsync({type: 'blob'})
            .then((content) => {
                saveAs(content, 'metadata.zip');
            });
    })
    /* ----- Download metadata end ----- */

    /* ----- Helpers ----- */
        /**
         * Delete helper
         */
        $(document).on('click', ids['helperDelete'], function() {
            let id = $(this).data('id');
            delete window.config.test.helpers[id];
        })

        /**
         * Switch helper
         */
        $(document).on('click', ids['helperSwitch'], function() {
            let id = $(this).data('id');
            window.config.test.helpers[id].active = !window.config.test.helpers[id].active;

            if(window.config.test.helpers[id].active)
                $(this)
                    .addClass('on')
                    .text('on')
            else
                $(this)
                    .removeClass('on')
                    .text('off')
        })
    /* ----- Helpers end ----- */


    /* ----- Drag'n'Drop helpers ----- */
        let processFileDrop = function(event, allowedFileTypes, callback) {
            event.stopPropagation();
            event.preventDefault();

            let files = event.originalEvent.target.files || event.originalEvent.dataTransfer.files;

            let output = [];
            let reader = new FileReader();


            for (let f of files) {
                if (allowedFileTypes.indexOf('*') === -1 && allowedFileTypes.indexOf(f.type) === -1) {
                    console.error(`Selected file with a type ${f.type} is not a memeber of ${allowedFileTypes}!`);
                    alert(`Selected file with a type ${f.type} is not a memeber of ${allowedFileTypes}!`);

                    continue
                }

                reader.onload = (function(file) {
                    return (e) => {
                        callback(e.target.result, file)
                    }
                })(f);

                // Read in the image file as a data URL.
                reader.readAsDataURL(f);
            }
        }
    /* ----- Drag'n'Drop helpers end----- */


    /* ----- Metadata Drag'n'Drop ----- */

        let showAuthenticatorInfo = (mds) => {
            if(mds) {
                $(ids['fileDropMetadata']).hide();
                $(ids['authenticatorInfo']).show();
                $(ids['authenticatorInfoContainer'])
                    .empty()
                    .html(render.authenticatorInfo(mds));
            }
        }

        let processMetadataInfo = (mds) => {
            window.config.test.metadataStatement = mds;
            showAuthenticatorInfo(mds)
        }

        let handleMetadataDrop = function(event) {
            processFileDrop(event, ['*'], (result, file) => {
                let base64content = result.replace(/(data:.*;base64),/, '');
                let decoded = atob(base64content);

                try {
                    let metadataStatement = JSON.parse(decoded)
                    processMetadataInfo(metadataStatement)
                } catch (err) {
                    console.error(`Selected metadata file is not a valid JSON file! Error ${err}`)
                }
            })
            this.value  = '';
        }

        /**
         * Clear metadata statement
         */
        $(ids['buttonClearAuthenticatorInfo'])
            .click((e) => {
                delete window.config.test.metadataStatement;
                $(ids['fileDropMetadata']).show();
                $(ids['authenticatorInfo']).hide();
            })

        /**
         * File drop
         */
        $(ids['fileDropMetadata'])
            .on('drop', handleMetadataDrop)
            .on('dragover', (event) => {
                event.stopPropagation();
                event.preventDefault();
            })
            /**
             * Click on the field triggers click 
             * on the hidden file input field
             * that opens file promt
             */
            .click((event) => {
                event.preventDefault();
                $(ids['filePromtMetadata']).trigger('click');
            })

        /**
         * Hidden file input field
         */
        $(ids['filePromtMetadata']).on('change', handleMetadataDrop);
    /* ----- Metadata Drag'n'Drop end ----- */


    /* ----- Polyfill Drag'n'Drop ----- */
        let handlePolyfillFileDrop = function(event) {
            processFileDrop(event, ['application/javascript', 'text/javascript', 'text/plain'], (result, file) => {
                if(!window.config.test.helpers)
                    window.config.test.helpers = {};

                let fileNode = {
                    'name': file.name,
                    'lastModified': file.lastModified,
                    'id': new Date().getTime().toString(),
                    'data': result.replace(/data:(application|text)\/javascript;base64,/, ''),
                    'active': true
                }

                window.config.test.helpers[fileNode.id] = fileNode;
            })  
            this.value  = '';
        }

        /**
         * File drop
         */
        $(ids['fileDropHelpers'])
            .on('drop', handlePolyfillFileDrop)
            .on('dragover', (event) => {
                event.stopPropagation();
                event.preventDefault();
            })
            /**
             * Click on the field triggers click 
             * on the hidden file input field
             * that opens file promt
             */
            .click((event) => {
                event.preventDefault();
                $(ids['filePromtHelpers']).trigger('click');
            })

        /**
         * Hidden file input field
         */
        $(ids['filePromtHelpers']).on('change', handlePolyfillFileDrop);
    /* ----- Polyfill Drag'n'Drop end ----- */

    /* ----- FIDO Authenticators List ----- */

        let fidoAuthenticators = {};
        window.setInterval(() => {
            /* If we actually need fido authenticator list */
            if (window.config.testSuit && arrayContainsItem(getRequiredFields(), 'fidoauthenticator') && !testsAreRunning) {
                fidoAuthenticators = {};

                if (window.config.test.fidoauthenticator) {
                    if(window.config.test.fidoauthenticator.transport === 'HID')
                        fidoAuthenticators[window.config.test.fidoauthenticator.path] = window.config.test.fidoauthenticator;
                    else
                        fidoAuthenticators[window.config.test.fidoauthenticator.product] = window.config.test.fidoauthenticator;
                }

                for(let authr of window.navigator.fido.fido2.hid.getDevices()) {
                    fidoAuthenticators[authr.path] = authr
                }

                for(let authr of window.navigator.fido.fido2.nfc.getAvailableReaders()) {
                    fidoAuthenticators[authr.product] = authr
                }

                for(let authr of window.navigator.fido.fido2.ble.getConnectedDevices()) {
                    fidoAuthenticators[authr.product] = authr
                }

                let html = '';
                for(let authrID in fidoAuthenticators) {
                    let authr = fidoAuthenticators[authrID];

                    let selectedAuthr = window.config.test.fidoauthenticator && (
                        (authr.path && authr.path === window.config.test.fidoauthenticator.path) 
                    ||  (authr.product === window.config.test.fidoauthenticator.product));

                    let state      = '';
                    let signalRSSI = '';
                    if(authr.transport === 'HID')
                        state = window.navigator.fido.fido2.hid.getState(authr);
                    else if (authr.transport === 'NFC')
                        state = window.navigator.fido.fido2.nfc.getState(authr);
                    else {
                        state      = window.navigator.fido.fido2.ble.getState(authr);
                        signalRSSI = window.navigator.fido.fido2.ble.getDeviceRSSI(authr);
                    }

                    html += render.fidoAuthenticator(authr, selectedAuthr, state, signalRSSI);
                }

                $(ids['FIDOAuthrList']).empty();
                $(ids['FIDOAuthrList']).append(html);
            }
        }, 2000)

        $(document).on('click', ids['FIDOAuthrOption'], function() {
            let authrID = $(this).val();
            delete window.config.test.fidoauthenticator;
            window.config.test.fidoauthenticator = fidoAuthenticators[authrID];
        })

    /* ----- FIDO Authenticators List end ----- */

    /* ----- AutoScroll ----- */
        // let autoScrollSetInterval = undefined;

        // let engageAutoScroll = () => {
        //     autoScrollSetInterval = setInterval(() => {
        //         $(ids['mochaDiv'])[0].scrollIntoView(false);
        //     }, 100)
        // }

        // let disengageAutoScroll = () => {
        //     if(autoScrollSetInterval)
        //         clearInverval(autoScrollSetInterval);
        // }

        // let mainEl = $('main')[0];
        // let lastScrollPosition = 0;
        // mainEl.addEventListener('scroll', (e) => {
        //     if(lastScrollPosition > mainEl.scrollTop) {
        //         // console.log('Going up')
        //         disengageAutoScroll();
        //     } else {
        //         if(testsAreRunning) {
        //             console.log('Going down')
        //             engageAutoScroll();
        //         } else {
        //             disengageAutoScroll();
        //         }
        //     }

        //     lastScrollPosition = mainEl.scrollTop;
        // }, true)

    /* ----- AutoScroll end ----- */

    window.loadTestSuitHtml = loadTestSuitHtml;
})()