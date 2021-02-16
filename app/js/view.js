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

let fieldDefinition = {
    'clientVendor' : {
        'title': 'Vendor Name',
        'type': 'string'
    },
    'serverURL' : {
        'title': 'Server URL',
        'type': 'string'
    },
    'aaid' : {
        'title': 'AAID',
        'type': 'string',
        'pattern': '\d{4}#\d{4}'

    },
    'username' : {
        'title': 'Username',
        'type': 'string'
    },
    'clientVersion' : {
        'title': 'Client Version',
        'type': 'object',
        'fieldDefinition': {
            'major': {
                'title': 'Major',
                'type': 'number',
                'min': 1,
                'max': 9
            },
            'minor': {
                'title': 'Minor',
                'type': 'number',
                'min': 0,
                'max': 9
            }
        }
    },
    'polyfills': {
        'type': 'html',
        'selector': '.fido__helpers'
    },
    'metadataStatement': {
        'type': 'html',
        'selector': '.fido__metadataStatement'
    },
    'downloadMetadata': {
        'type': 'button',
        'title': 'Download server metadata',
        'class': 'fido__metadata--download'
    },
    'fidoauthenticator': {
        'type': 'html',
        'selector': '.fido__fidoauthenticators'
    },
    'fido2OptionalAlgorithms': {
        'title': 'Server support for OPTIONAL algorithms and attestations',
        'type': 'object',
        'fieldDefinition': {
            'ANDROID_KEYSTORE_ATTESTATION': {
                'title': 'Android Keystore Attestation',
                'type': 'checkbox'
            },
            'ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW': {
                'title': 'ECDSA SECP256K1 SHA256',
                'type': 'checkbox'
            },
            'ALG_SIGN_RSASSA_PSS_SHA256_RAW': {
                'title': 'RSASSA PSS SHA256',
                'type': 'checkbox'
            },
            'ALG_SIGN_RSASSA_PSS_SHA384_RAW': {
                'title': 'RSASSA PSS SHA384',
                'type': 'checkbox'
            },
            'ALG_SIGN_RSASSA_PSS_SHA512_RAW': {
                'title': 'RSASSA PSS SHA512',
                'type': 'checkbox'
            },
            'ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW': {
                'title': 'RSASSA PKCSV15 SHA384',
                'type': 'checkbox'
            },
            'ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW': {
                'title': 'RSASSA PKCSV15 SHA512',
                'type': 'checkbox'
            },
            'ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW': {
                'title': 'ECDSA SECP384R1 SHA384',
                'type': 'checkbox'
            },
            'ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW': {
                'title': 'ECDSA SECP521R1 SHA512',
                'type': 'checkbox'
            },
            'ALG_SIGN_ED25519_EDDSA_SHA512_RAW': {
                'title': 'ED25519 EDDSA SHA512',
                'type': 'checkbox'
            }
        }
    }
}

let generateAttributes = (descriptor) => {
    let ignoredKeys = ['title'];
    let attributes = '';

    for(let key in descriptor) {
        if(ignoredKeys.indexOf(key) !== -1)
            continue;

        attributes += `${key}="${descriptor[key]}" `;
    }

    return attributes
}

let show = {
    'error': (message) => {
        let container = $('#fido__snackbar')[0];
        container.MaterialSnackbar.showSnackbar({
            message: message,
            actionHandler: () => container.classList.remove('mdl-snackbar--active'),
            timeout: 2000,
            actionText: 'x'
        });
    }
}

let render = {
    'testLists' : (testlists) => {

        let content = '';

        for(let key in testlists) {
            if(!testlists[key])
                continue

            let checked = key === window.config.testList ? 'checked' : '';
            let testlist = testlists[key];
            let id = generateRandomString();
            content += `
                <div class="fido__testlist">
                    <label for="${id}" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">
                        <input type="checkbox" data-key="${key}" ${checked} data-type="testlist" id="${id}" class="mdl-checkbox__input fido__testlist__item fido__testlist__option">
                        <span class="mdl-checkbox__label">${testlist.name}</span>
                    </label>
                    <div class="mdl-cell mdl-cell--12-col">
                        <ul>
                            ${render.testCases(key, testlist.tests)}
                        </ul>
                    </div>
                </div>
            `;
        }

        return content
    },

    'testCases' : (parent, tests) => {
        let content = '';

        for(let key in tests) {

            let testcase = tests[key];
            let id = generateRandomString();
            let checked = '';

            if(parent === window.config.testList)
                if(window.config.testCases.indexOf(key) !== -1)
                    checked = 'checked';

            content += `
                 <li>
                    <label for="${id}" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">
                        <input data-key="${key}" data-parent="${parent}" ${checked} data-type="testcase" type="checkbox" id="${id}" class="fido__testlist__item fido__testcase__option mdl-checkbox__input">
                        <span class="mdl-checkbox__label">${testcase.name}</span>
                    </label>
                </li>
            `;
        }

        return content
    },

    'configOption' : (key, descriptor, parent) => {
        let id = generateRandomString();
        let value = '';

        if(!parent) parent = '';

        if(parent !== '' && parent !== undefined && parent !== 'undefined') {
            if(window.config.test[parent])
                value = window.config.test[parent][key];
        } else
            value = window.config.test[key] || '';

        if(descriptor.type === 'checkbox')
            return `
                <div>
                    <input class="fido__config__option" ${value ? 'checked' : ''} data-key="${key}" data-parent="${parent}" ${generateAttributes(descriptor)} type="${descriptor.type}" id="${id}">
                    <label for="${id}">${descriptor.title}</label>
                </div>
            `;
        else
            return `
                <div class="mdl-textfield mdl-js-textfield">
                    <input class="fido__config__option mdl-textfield__input" value="${value}" data-key="${key}" data-parent="${parent}" ${generateAttributes(descriptor)} type="${descriptor.type}" id="${id}">
                    <label class="mdl-textfield__label" for="${id}">${descriptor.title}</label>
                </div>
            `;
    },

    'configOptionObject': (parent, descriptor) => {
        let content = '';

        for(let key in descriptor.fieldDefinition)
            content += `
                <div class="mdl-cell mdl-cell--8-col">
                    ${render.configOption(key, descriptor.fieldDefinition[key], parent)}
                </div>
            `

        return `
            <span class="field-title mdl-textfield mdl-js-textfield is-upgraded">${descriptor.title}</span>
            <div class="mdl-grid">
               ${content}
            </div>
        `
    },

    'configOptionButton': (title, cssClass) => {
        return `
            <button class="${cssClass} mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-color--grey-100 mdl-color-text--grey-600">
                ${title}
            </button>
        `
    },

    'configOptionCheckbox': (title, cssClass, key, checked) => {
        let id = generateRandomString();
        return `
            <label for="${id}" class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect">
                <input type="checkbox" data-key="${key}" ${checked} data-type="testlist" id="${id}" class="mdl-checkbox__input ${cssClass}">
                <span class="mdl-checkbox__label">${title}</span>
            </label>
        `
    },

    'configOptions': (options) => {
        let content = '';
        
        for(let option of options) {
            let descriptor = fieldDefinition[option]

            if(descriptor) {
                switch(descriptor.type) {
                    case 'html':
                        $(descriptor.selector)
                            .show();
                    break

                    case 'button':
                        content += render.configOptionButton(descriptor.title, descriptor.class);
                    break

                    // case 'checkbox':
                    //     content += render.configOptionCheckbox(descriptor.title, descriptor.class);
                    // break

                    case 'object':
                        content += render.configOptionObject(option, descriptor);
                    break

                    default:
                        content += render.configOption(option, descriptor);
                    break

                }
            } else {
                console.error(`Unknown field descriptor ${option}`)
            }
        }

        return content
    },

    'helpers': (helpers) => {
        let content = '';

        for(let key in helpers) {
            let helper = helpers[key];
            let date = new Date(helper.lastModified);
            let lastModified = `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
            content += `
                <span class="mdl-chip mdl-chip--contact mdl-chip--deletable">
                    <span data-id="${helper.id}" class="fido__test__helpers--switch ${helper.active ? 'on' : ''} mdl-chip__contact mdl-color--teal mdl-color-text--white">${helper.active ? 'on' : 'off'}</span>
                    <span class="mdl-chip__text">${helper.name} [${lastModified}]</span>

                    <a href="#" data-id="${helper.id}" class="fido__test__helpers--delete mdl-chip__action"><i class="material-icons">cancel</i></a>
                </span>
            `;
        }

        return content
    },

    'testSuitCards': (manifestos) => {
        let content = '';

        for(let manifesto of manifestos) {
            content += `
                <div class="fido__test__suit__select mdl-card mdl-shadow--2dp">
                    <div class="mdl-card__title mdl-card--expand">
                        <h4>
                            ${manifesto.name} ${manifesto.protocolVersion} 
                            ${manifesto.description}
                        </h4>
                    </div>
                    <div class="mdl-card__actions mdl-card--border">
                        <a data-id="${manifesto.id}" class="fido__test__suit__select--button mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect">
                            Run
                        </a>
                    </div>
                </div>
            `
        }

        return content
    },

    'authenticatorInfo': (metadataStatement) => {
        return `
            <img src="${metadataStatement.icon}" class="fido__authenticator_info--icon">

            <span>${metadataStatement.description}</span>
            <p><b>${metadataStatement.aaid || metadataStatement.aaguid || metadataStatement.attestationCertificateKeyIdentifiers[0]}</b></p>
            <p><b>version: </b>${metadataStatement.authenticatorVersion}</p>
            <p><b>protocol: </b>${metadataStatement.protocolFamily}</p>
            <p><b>signature: </b>${metadataStatement.authenticationAlgorithm}</p>
            <p><b>publickey: </b>${metadataStatement.publicKeyAlgAndEncoding}</p>
            <p><b>2nd factor: </b>${metadataStatement.isSecondFactorOnly}</p>
        `
    },

    'fidoAuthenticator': (deviceInfo, checked, state, signalRSSI) => {
        return `
            <li class="mdl-list__item fido__fidoauthenticators__authr">
                <span class="mdl-list__item-primary-content">
                    [${deviceInfo.transport}] ${deviceInfo.product} ${state.toUpperCase()} ${signalRSSI ? signalRSSI + 'db' : ''}
                </span>
                <span class="mdl-list__item-secondary-action">
                    <label class="mdl-radio mdl-js-radio mdl-js-ripple-effect" for="list-option-${deviceInfo.path || deviceInfo.product}">
                        <input type="radio" id="list-option-${deviceInfo.path || deviceInfo.product}" class="mdl-radio__button fido__fidoauthenticators__authr-option" name="options" value="${deviceInfo.path || deviceInfo.product}" ${checked ? 'checked' : ''} />
                    </label>
                </span>
            </li>
        `
    }
}

/* ----- 

    Hey, look, buddy.
    I'm an engineer.
    That means I solve problems.
    Not problems like "What is Angular/React/etc?", because that would fall within the purview of your conundrums of web development.
    I solve practical problems.
    For instance, how am I gonna implement a complicated test framework in a month, while being on vacation?
    The answer: use a jQuery.
    And if that don't work?
    Use more jQuery.
    Like this heavy-caliber Material Design Lite jQuery Mocha Chai FIDO conformance testing framework designed by me...
    ...built by me..
    ...and you best hope...
    ...it's not pointed at you.

----- */