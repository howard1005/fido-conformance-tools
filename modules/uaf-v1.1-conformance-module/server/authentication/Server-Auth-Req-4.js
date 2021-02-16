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

        Server-Auth-Req-4

        Test the Policy dictionary

    `, function() {

    let authenticationRequest;
    let policy;
    before(() => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((response) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then((success) => rest.authenticate.get(1200, username))
            .then((data) => {
                authenticationRequest = data[0];
                policy = authenticationRequest.policy;
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Policy "policy" MUST be of type Dictionary can contain ony "accepted" and "disallowed" keys.

    `, () => {
        assert.isObject(policy, 'Policy MUST be of type DICTIONARY!');

        for(let key in policy) {
            assert.isTrue(key === 'accepted' || key === 'disallowed', 'Policy MUST only contain "accepted" and "disallowed" keys!');
        }
    })

    it(`P-2

        Policy.accepted MUST be of type Two-Dimentional SEQUENCE([][])

    `, () => {
        assert.isArray(policy.accepted, 'Policy MUST be of type SEQUENCE!');

        for (let secondDimension of policy.accepted) {
            assert.isArray(secondDimension, 'Policy MUST contain only SEQUENCE items!');
        }
    })

    it(`P-3

        For each MatchCriteria element in Policy.accepted check that: 
            (a) If "aaid" presented, it MUST be of type SEQUENCE, containing elements of type AAID 
            (b) If "vendorID" presented, it MUST be of type SEQUENCE, containing elements of type DOMString 
            (c) If "keyIDs" presented, it MUST be of type SEQUENCE, containing elements of type KeyID 
            (d) If "userVerification" presented, it MUST be of type NUMBER 
            (e) If "keyProtection" presented, it MUST be of type NUMBER 
            (f) If "matcherProtection" presented, it MUST be of type NUMBER 
            (g) If "attachmentHint" presented, it MUST be of type NUMBER 
            (h) If "tcDisplay" presented, it MUST be of type NUMBER 
            (i) If "authenticationAlgorithms" presented, it MUST be of type SEQUENCE and only contain items of type NUMBER  
            (j) If "assertionSchemes" presented, it MUST be of type NUMBER 
            (k) If "attestationTypes" presented, it MUST be of type SEQUENCE, and each element is of type NUMBER that is corresponding to one of the TAG_ATTESTATION in UAF Registry 
            (l) If "authenticatorVersion" presented, it MUST be of type NUMBER 
            (m) If "exts" presented, it MUST be of type SEQUENCE, if it contains any members, each member MUST be: 
                (i) of type dictionary 
                (ii) MUST contain "id" field, of type DOMString, with minimum length 1 character, and maximum length 32 characters. 
                (iii) MUST contain "data" field, of type DOMString, and use base64url encoding 
                (iv) MUST contain "fail_if_unknown" field, of type Boolean

    `, () => {
        for (let secondDimension of policy.accepted) {
            for (let MatchCriteria of secondDimension) {
                if(MatchCriteria.aaid)
                    assert.isArray(MatchCriteria.aaid, 'MatchCriteria.aaid MUST be of type SEQUENCE');

                if(MatchCriteria.vendorID)
                    assert.isArray(MatchCriteria.vendorID, 'MatchCriteria.vendorID MUST be of type SEQUENCE');

                if(MatchCriteria.keyIDs)
                    assert.isArray(MatchCriteria.keyIDs, 'MatchCriteria.keyIDs MUST be of type SEQUENCE');

                if(MatchCriteria.userVerification)
                    assert.isNumber(MatchCriteria.userVerification, 'MatchCriteria.userVerification MUST be of type NUMBER');

                if(MatchCriteria.keyProtection)
                    assert.isNumber(MatchCriteria.keyProtection, 'MatchCriteria.keyProtection MUST be of type NUMBER');

                if(MatchCriteria.matcherProtection)
                    assert.isNumber(MatchCriteria.matcherProtection, 'MatchCriteria.matcherProtection MUST be of type NUMBER');

                if(MatchCriteria.attachmentHint)
                    assert.isNumber(MatchCriteria.attachmentHint, 'MatchCriteria.attachmentHint MUST be of type NUMBER');

                if(MatchCriteria.tcDisplay)
                    assert.isNumber(MatchCriteria.tcDisplay, 'MatchCriteria.tcDisplay MUST be of type NUMBER');

                if(MatchCriteria.authenticationAlgorithms) {
                    assert.isArray(MatchCriteria.authenticationAlgorithms, 'MatchCriteria.authenticationAlgorithms MUST be of type SEQUENCE');
                    for(let item of MatchCriteria.authenticationAlgorithms)
                        assert.isNumber(item, `MatchCriteria.authenticationAlgorithms contains an item "${item}" that is NOT of type NUMBER`);
                }

                if(MatchCriteria.assertionSchemes) {
                    assert.isArray(MatchCriteria.assertionSchemes, 'MatchCriteria.assertionSchemes MUST be of type SEQUENCE');
                    for(let assertionScheme of MatchCriteria.assertionSchemes)
                        assert.isString(assertionScheme, 'AssertionScheme MUST be of type DOMString!');
                }

                if(MatchCriteria.attestationTypes) {
                    assert.isArray(MatchCriteria.attestationTypes, 'MatchCriteria.attestationTypes MUST be of type SEQUENCE');

                    for(let member of MatchCriteria.attestationTypes) {
                        assert.isNumber(member, `MatchCriteria.attestationTypes contains a member "${member}" that is NOT of type NUMBER!`);
                        assert.isTrue(member === PREDEFINED_TAGS.TAG_ATTESTATION_BASIC_FULL || member === PREDEFINED_TAGS.TAG_ATTESTATION_BASIC_SURROGATE, `MatchCriteria.attestationTypes contains a member "${member}" that is that is not isDefined as a valid attestation type in Registry of Predefined values!`);
                    }
                }

                if(MatchCriteria.authenticatorVersion)
                    assert.isNumber(MatchCriteria.authenticatorVersion, 'MatchCriteria.authenticatorVersion MUST be of type NUMBER');

                if(MatchCriteria.exts) {
                    assert.isArray(MatchCriteria.exts, 'MatchCriteria.exts MUST be of type SEQUENCE');

                    for (let extension of authenticationRequest.header.exts) {
                        assert.isString(extension.id, 'Extension.id MUST be of type DOMString!');
                        assert.isAtLeast(extension.id, 1, 'Extension.id MUST be at least 1 character long!');
                        assert.isAtMost(extension.id, 32, 'Extension.id can be max of 32 characters long!');

                        assert.isString(extension.data, 'Extension.data MUST be of type DOMString!');
                        assert.match(extension.data, /^[a-zA-Z0-9_-]+$/, 'Extension.data MUST be base64URL(without padding) encoded!');

                        assert.isBoolean(extension.fail_if_unknown, 'Extension.id MUST be of type DOMString!');
                    }
                }
            }
        }
    })

    it(`P-4

        For each MatchCriteria element in Policy.accepted, that contain "aaid" field, check that "aaid" MUST not be combined with ANY other field, but: "keyIDs", "attachmentHint", "authenticatorVersion", and "exts"

    `, () => {
        for (let secondDimension of policy.accepted) {
            for (let MatchCriteria of secondDimension) {
                if(MatchCriteria.aaid) {
                    for (let key in MatchCriteria) {
                        assert.include(['keyIDs', 'attachmentHint', 'authenticatorVersion', 'exts', 'aaid'], key, 'AAID can only be combined with "keyIDs", "attachmentHint", "authenticatorVersion", and "exts" fields!');
                    }
                }
            }
        }
    })

    it(`P-5

        For each MatchCriteria in Policy.accepted, if MatchCriteria DOES NOT contain "aaid" field, BOTH "authenticationAlgorithms" and "assertionSchemes" MUST be presented

    `, () => {
        for (let secondDimension of policy.accepted) {
            for (let MatchCriteria of secondDimension) {
                if(!MatchCriteria.aaid) {
                    assert.isDefined(MatchCriteria.authenticationAlgorithms, 'If AAID is missing, authenticationAlgorithms MUST be presented!');
                    assert.isDefined(MatchCriteria.assertionSchemes, 'If AAID is missing, assertionSchemes MUST be presented!');
                }
            }
        }
    })

    it(`P-6

        Policy.disallowed MUST be of type SEQUENCE

    `, () => {
        if(policy.disallowed) {
            assert.isArray(policy.disallowed, 'Policy MUST be of type SEQUENCE!');
        }
    })

    it(`P-7

        For each MatchCriteria element in Policy.disallowed check that: 
            (a) If "aaid" presented, it MUST be of type SEQUENCE, containing elements of type AAID 
            (b) If "vendorID" presented, it MUST be of type SEQUENCE, containing elements of type DOMString 
            (c) If "keyIDs" presented, it MUST be of type SEQUENCE, containing elements of type KeyID 
            (d) If "userVerification" presented, it MUST be of type NUMBER 
            (e) If "keyProtection" presented, it MUST be of type NUMBER 
            (f) If "matcherProtection" presented, it MUST be of type NUMBER 
            (g) If "attachmentHint" presented, it MUST be of type NUMBER 
            (h) If "tcDisplay" presented, it MUST be of type NUMBER 
            (i) If "authenticationAlgorithms" presented, it MUST be of type SEQUENCE and only contain items of type NUMBER  
            (j) If "assertionSchemes" presented, it MUST be of type NUMBER 
            (k) If "attestationTypes" presented, it MUST be of type SEQUENCE, and each element is of type NUMBER that is corresponding to one of the TAG_ATTESTATION in UAF Registry 
            (l) If "authenticatorVersion" presented, it MUST be of type NUMBER 
            (m) If "exts" presented, it MUST be of type SEQUENCE, if it contains any members, each member MUST be: 
                (i) of type dictionary 
                (ii) MUST contain "id" field, of type DOMString, with minimum length 1 character, and maximum length 32 characters. 
                (iii) MUST contain "data" field, of type DOMString, and use base64url encoding 
                (iv) MUST contain "fail_if_unknown" field, of type Boolean
    `, () => {
        if(policy.disallowed) {
            for (let MatchCriteria of policy.disallowed) {
                if(MatchCriteria.aaid)
                    assert.isArray(MatchCriteria.aaid, 'MatchCriteria.aaid MUST be of type SEQUENCE');

                if(MatchCriteria.vendorID)
                    assert.isArray(MatchCriteria.vendorID, 'MatchCriteria.vendorID MUST be of type SEQUENCE');

                if(MatchCriteria.keyIDs)
                    assert.isArray(MatchCriteria.keyIDs, 'MatchCriteria.keyIDs MUST be of type SEQUENCE');

                if(MatchCriteria.userVerification)
                    assert.isNumber(MatchCriteria.userVerification, 'MatchCriteria.userVerification MUST be of type NUMBER');

                if(MatchCriteria.keyProtection)
                    assert.isNumber(MatchCriteria.keyProtection, 'MatchCriteria.keyProtection MUST be of type NUMBER');

                if(MatchCriteria.matcherProtection)
                    assert.isNumber(MatchCriteria.matcherProtection, 'MatchCriteria.matcherProtection MUST be of type NUMBER');

                if(MatchCriteria.attachmentHint)
                    assert.isNumber(MatchCriteria.attachmentHint, 'MatchCriteria.attachmentHint MUST be of type NUMBER');

                if(MatchCriteria.tcDisplay)
                    assert.isNumber(MatchCriteria.tcDisplay, 'MatchCriteria.tcDisplay MUST be of type NUMBER');

                if(MatchCriteria.authenticationAlgorithms) {
                    assert.isArray(MatchCriteria.authenticationAlgorithms, 'MatchCriteria.authenticationAlgorithms MUST be of type SEQUENCE');
                    for(let item of MatchCriteria.authenticationAlgorithms)
                        assert.isNumber(item, `MatchCriteria.authenticationAlgorithms contains an item "${item}" that is NOT of type NUMBER`);
                }

                if(MatchCriteria.assertionSchemes) {
                    assert.isArray(MatchCriteria.assertionSchemes, 'MatchCriteria.assertionSchemes MUST be of type SEQUENCE');
                    for(let assertionScheme of MatchCriteria.assertionSchemes)
                        assert.isString(assertionScheme, 'AssertionScheme MUST be of type DOMString!');
                }

                if(MatchCriteria.attestationTypes) {
                    assert.isArray(MatchCriteria.attestationTypes, 'MatchCriteria.attestationTypes MUST be of type SEQUENCE');

                    for(let member of MatchCriteria.attestationTypes) {
                        assert.isNumber(member, `MatchCriteria.attestationTypes contains a member "${member}" that is NOT of type NUMBER!`);
                        assert.isTrue(member === PREDEFINED_TAGS.TAG_ATTESTATION_BASIC_FULL || member === PREDEFINED_TAGS.TAG_ATTESTATION_BASIC_SURROGATE, `MatchCriteria.attestationTypes contains a member "${member}" that is that is not isDefined as a valid attestation type in Registry of Predefined values!`);
                    }
                }

                if(MatchCriteria.authenticatorVersion)
                    assert.isNumber(MatchCriteria.authenticatorVersion, 'MatchCriteria.authenticatorVersion MUST be of type NUMBER');

                if(MatchCriteria.exts) {
                    assert.isArray(MatchCriteria.exts, 'MatchCriteria.exts MUST be of type SEQUENCE');

                    for (let extension of authenticationRequest.header.exts) {
                        assert.isString(extension.id, 'Extension.id MUST be of type DOMString!');
                        assert.isAtLeast(extension.id, 1, 'Extension.id MUST be at least 1 character long!');
                        assert.isAtMost(extension.id, 32, 'Extension.id can be max of 32 characters long!');

                        assert.isString(extension.data, 'Extension.data MUST be of type DOMString!');
                        assert.match(extension.data, /^[a-zA-Z0-9_-]+$/, 'Extension.data MUST be base64URL(without padding) encoded!');

                        assert.isBoolean(extension.fail_if_unknown, 'Extension.id MUST be of type DOMString!');
                    }
                }
            }
        }
    })

    it(`P-8

        For each MatchCriteria element in Policy.disallowed, that contain "aaid" field, check that "aaid" MUST not be combined with ANY other field, but: "keyIDs", "attachmentHint", "authenticatorVersion", and "exts"

    `, () => {
        if(policy.disallowed) {
            for (let MatchCriteria of policy.disallowed) {
                if(MatchCriteria.aaid) {
                    for (let key in MatchCriteria) {
                        assert.include(['keyIDs', 'attachmentHint', 'authenticatorVersion', 'exts', 'aaid'], key, 'AAID can only be combined with "keyIDs", "attachmentHint", "authenticatorVersion", and "exts" fields!');
                    }
                }
            }
        }
    })

    it(`P-9

        For each MatchCriteria in Policy.disallowed, if MatchCriteria DOES NOT contain "aaid" field, BOTH "authenticationAlgorithms" and "assertionSchemes" MUST be presented 

    `, () => {
        if(policy.disallowed) {
            for (let MatchCriteria of policy.disallowed) {
                if(!MatchCriteria.aaid) {
                    assert.isDefined(MatchCriteria.authenticationAlgorithms, 'If AAID is missing, authenticationAlgorithms MUST be presented!');
                    assert.isDefined(MatchCriteria.assertionSchemes, 'If AAID is missing, assertionSchemes MUST be presented!');
                }
            }
        }
    })

    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    })

    it(`P-10

        Register second-factor only roaming authenticator the target server, and check that server returns registered KeyID mixed with "aaid" of the authenticator in the "accepted" Two-Dimentional SEQUENCE([]][]) MatchCriteria.

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC2F');
        let registrationPair = undefined;

        return rest.register.get(1200, username)
            .then((data) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(data)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let message         = tryDecodeJSON(data.uafProtocolMessage)[0];
                let assertionBuffer = base64url.decode(message.assertions[0].assertion);
                let ASSERT_STRUCT   = tlv.parser.parse(assertionBuffer);

                registrationPair = {
                    'aaid': [ASSERT_STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_AAID],
                    'keyIDs': [ASSERT_STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_KEYID]
                }

                return rest.register.post(data.uafProtocolMessage, 1200, username)
            })
            .then(() => {
                return rest.authenticate.get(1200, username)
            })
            .then((data) => {
                let authenticationRequest = data[0];

                assert.deepInclude(authenticationRequest.policy.accepted, [registrationPair], `For Second-Factor only authenticator, Server MUST return a Policy.accepted(${JSON.stringify(authenticationRequest.policy.accepted, null, 4)}) that contain registration KeyID/AAID pair(${JSON.stringify([registrationPair])})`);
            })
    })
})