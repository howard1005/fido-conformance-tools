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

        Resident-Key

        Test Resident-Key support

    `, function() {

    let authenticatorWithDisplay = false;
    let supportedOptions         = undefined;
    let supportsClientPin1       = false;
    before(function() {
        this.timeout(30000);
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        return sendValidCTAP_CBOR(generateGetInfoRequest())
            .then((ctap2Response) => {
                let cborResponse = ctap2Response.cborResponse;

                let pinProtocols = cborResponse[GetInfoRespKeys.pinProtocols];
                supportsClientPin1 = arrayContainsItem(pinProtocols || [], 0x01);

                supportedOptions = cborResponse[GetInfoRespKeys.options];
                if(!supportedOptions || !supportedOptions.rk)
                    this.skip()
                else
                    authenticatorWithDisplay = confirm('Does your authenticator support display?');
            })
    })

    after(function() {
        this.timeout(30000);
        return sendReset()
    })

    this.timeout(60000);
    // this.retries(3);

/* ----- POSITIVE TESTS ----- */

    it(`P-1

        Send a valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, wait for the response, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

    `, () => {
        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let options = {
            'rk': true
        }

        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, makeCredStruct.rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)

        return sendValidCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);
            })
    })


    it(`P-2
    
        FOR AUTHENTICATORS WITHOUT A DISPLAY AND UV IS FALSE

        Send three valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, and if authenticator supports UV option set "uv" to false, wait for the responses, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with no allowList presented, wait for the response and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Check that response contains "numberOfCredentials" field that is of type Number and is set to 3.

        Send authenticatorGetNextAssertion(0x08), until numberOfCredentials is 1, retrieve responses and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code for each of the requests. Check that response.user ONLY contains id field and nothing else!

    `, function() {
        if(authenticatorWithDisplay)
            this.skip()

        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let options = {
            'rk': true
        }

        if(supportedOptions.uv)
            options.uv = false;

        let users = {};
        users[hex.encode(makeCredStruct.user.id)] = makeCredStruct.user
        let rp = makeCredStruct.rp;
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)


        let allAssertions = [];
        return sendValidCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                let makeCredStruct = generateGoodCTAP2MakeCreditentials();
                let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)
                users[hex.encode(makeCredStruct.user.id)] = makeCredStruct.user

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((ctap2Response) => {
                let makeCredStruct = generateGoodCTAP2MakeCreditentials();
                let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)
                users[hex.encode(makeCredStruct.user.id)] = makeCredStruct.user

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((response) => {
                let goodAssertion = generateGoodCTAP2GetAssertion(origin);
                let getAssertionBuffer = generateGetAssertionReqCBOR(rp.id, goodAssertion.clientDataHash)

                return sendValidCTAP_CBOR(getAssertionBuffer, {'dontResetCard': true})
            })
            .then((ctap2Response) => {
                allAssertions.push(ctap2Response)

                let cborResponse = ctap2Response.cborResponse;

                let credentialCounter = cborResponse[GetAssertionRespKeys.numberOfCredentials] - 1;
                assert.strictEqual(cborResponse[GetAssertionRespKeys.numberOfCredentials], 3, '3 credentials been registered! Expected 3, got ' + cborResponse[GetAssertionRespKeys.numberOfCredentials])

                return getRemainingGetNextCredentials(credentialCounter)
            })
            .then((restAssertions) => {
                allAssertions = allAssertions.concat(restAssertions);

                let first = true;
                for(let i = 0; i < allAssertions.length; i++) {
                    let cborResponse       = allAssertions[i].cborResponse;
                    let cborResponseStruct = allAssertions[i].cborResponseStruct;

                    if(cborResponse[GetAssertionRespKeys.numberOfCredentials] && !first)
                        throw new Error('numberOfCredentials field MUST be omitted after first assertion!');

                    first = false;

                    if(cborResponse[GetAssertionRespKeys.credential]) {
                        assert.isObject(cborResponse[GetAssertionRespKeys.credential], 'GetAssertion_Response.credential MUST be of type MAP!');

                        assert.strictEqual(type(cborResponseStruct[GetAssertionRespKeys.credential].id), 'Uint8Array', 'credential.id MUST be of type BYTE STRING!');
                        assert.isAbove(cborResponseStruct[GetAssertionRespKeys.credential].id.byteLength, 0, 'credential.id MUST not be empty!');

                        assert.isString(cborResponse[GetAssertionRespKeys.credential].type, 'credential.id MUST be of type STRING!');
                        assert.strictEqual(cborResponse[GetAssertionRespKeys.credential].type, 'public-key', 'credential.type MUST strictly equal to "public-key"!');
                    }

                    let user = cborResponse[GetAssertionRespKeys.user];
                    assert.isDefined(user, 'GetAssertion_Response missing "user" field! For Device Resident Key credential, "user" field MUST be present.')
                    assert.isObject(user, 'GetAssertion_Response.user MUST be of type MAP!');

                    assert.isDefined(user.id, 'user missing "id" field!');
                    assert.strictEqual(type(cborResponseStruct[GetAssertionRespKeys.user].id), 'Uint8Array', 'user.id MUST be of type BYTE STRING!');

                    assert.deepEqual(Object.keys(user), ['id'], 'For CTAP2 request that was not verified, GetAssertion_Response.user MUST only contain "id" field!');

                    let userInfo = users[user.id];
                    assert.isDefined(userInfo, `User with user.id "${user.id}" was never registered!`);

                }
            })
    })

    it(`P-3
        
        FOR AUTHENTICATORS WITHOUT A DISPLAY AND EITHER UV IS TRUE OR CLIENTPIN IS USED

        If UV option is supported, set UV to true.
        Else set new pin, and run registrations with pin.
        Else skip this test.

        Send two valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, and if authenticator supports UV option set "uv" to true, wait for the responses, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

        Send a valid CTAP2 authenticatorGetAssertion(0x02) message, with no allowList presented, wait for the response and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Check that response contains "numberOfCredentials" field that is of type Number and is set to 2.

        Send authenticatorGetNextAssertion(0x08), until numberOfCredentials is 1, retrieve responses and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code for each of the requests. Check that response.user contains all of the registered userInfo

    `, function() {
        if(authenticatorWithDisplay || !(supportsClientPin1 || supportedOptions.uv))
            this.skip()

        let options = {
            'rk': true
        }

        if(supportedOptions.uv)
            options.uv = true;

        let rp = {
            name: 'The Example Corporation with fake domain!',
            id: 'https://' + generateRandomDomain()
        }

        let users = {};

        let pincode = leftpad(generateSecureRandomInt(0, 100000000), 6);
        let sendMakeCredWithPinOrNot = () => {
            let makeCredStruct = generateGoodCTAP2MakeCreditentials();
            users[hex.encode(makeCredStruct.user.id)] = makeCredStruct.user

            if(supportsClientPin1 && !supportedOptions.uv) {
                return getPINToken(pincode)
                    .then((pinToken) => {
                        let pinHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(pinToken, makeCredStruct.clientDataHash);
                        let pinAuth = pinHMAC.slice(0, 16);

                        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options, pinAuth, 0x01)

                        return sendValidCTAP_CBOR(commandBuffer, {'dontResetCard': true})
                    })

            } else {
                let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)

                return sendValidCTAP_CBOR(commandBuffer, {'dontResetCard': true})
            }
        }

        let sendGetAssertionWithPinOrNot = () => {
            let goodAssertion = generateGoodCTAP2GetAssertion(origin);

            if(supportsClientPin1 && !supportedOptions.uv) {
                return getPINToken(pincode)
                .then((pinToken) => {
                    let pinHMAC = window.navigator.fido.fido2.crypto.generateHMACSHA256(pinToken, goodAssertion.clientDataHash);
                    let pinAuth = pinHMAC.slice(0, 16);

                    let getAssertionBuffer = generateGetAssertionReqCBOR(rp.id, goodAssertion.clientDataHash, undefined, undefined, undefined, pinAuth, 0x01)

                    return sendValidCTAP_CBOR(getAssertionBuffer, {'dontResetCard': true})
                })
            } else {
                let getAssertionBuffer = generateGetAssertionReqCBOR(rp.id, goodAssertion.clientDataHash, undefined, undefined, {'uv': true})

                return sendValidCTAP_CBOR(getAssertionBuffer, {'dontResetCard': true})
            }
        }

        let setUpPinIfAvailable = () => {
            if(supportsClientPin1 && !supportedOptions.uv)
                return setNewPincode(pincode)
            else
                return Promise.resolve()
        }


        let allAssertions = [];
        return setUpPinIfAvailable()
            .then(() => sendMakeCredWithPinOrNot())
            .then(() => sendMakeCredWithPinOrNot())
            .then(() => sendGetAssertionWithPinOrNot())
            .then((ctap2Response) => {
                allAssertions.push(ctap2Response)

                let cborResponse = ctap2Response.cborResponse;

                let credentialCounter = cborResponse[GetAssertionRespKeys.numberOfCredentials] - 1;
                assert.strictEqual(cborResponse[GetAssertionRespKeys.numberOfCredentials], 2, '2 credentials been registered! Expected 2, got ' + cborResponse[GetAssertionRespKeys.numberOfCredentials])

                return getRemainingGetNextCredentials(credentialCounter)
            })
            .then((restAssertions) => {
                allAssertions = allAssertions.concat(restAssertions);

                let first = true;
                for(let i = 0; i < allAssertions.length; i++) {
                    let cborResponse       = allAssertions[i].cborResponse;
                    let cborResponseStruct = allAssertions[i].cborResponseStruct;

                    if(cborResponse[GetAssertionRespKeys.numberOfCredentials] && !first)
                        throw new Error('numberOfCredentials field MUST be omitted after first assertion!');

                    first = false;

                    if(cborResponse[GetAssertionRespKeys.credential]) {
                        assert.isObject(cborResponse[GetAssertionRespKeys.credential], 'GetAssertion_Response.credential MUST be of type MAP!');

                        assert.strictEqual(type(cborResponseStruct[GetAssertionRespKeys.credential].id), 'Uint8Array', 'credential.id MUST be of type BYTE STRING!');
                        assert.isAbove(cborResponseStruct[GetAssertionRespKeys.credential].id.byteLength, 0, 'credential.id MUST not be empty!');

                        assert.isString(cborResponse[GetAssertionRespKeys.credential].type, 'credential.id MUST be of type STRING!');
                        assert.strictEqual(cborResponse[GetAssertionRespKeys.credential].type, 'public-key', 'credential.type MUST strictly equal to "public-key"!');
                    }

                    let user = cborResponse[GetAssertionRespKeys.user];
                    assert.isDefined(user, 'GetAssertion_Response missing "user" field! For Device Resident Key credential, "user" field MUST be present.')
                    assert.isObject(user, 'GetAssertion_Response.user MUST be of type MAP!');

                    assert.isDefined(user.id, 'user missing "id" field!');
                    assert.strictEqual(type(cborResponseStruct[GetAssertionRespKeys.user].id), 'Uint8Array', 'user.id MUST be of type BYTE STRING!');

                    let userInfo = users[user.id];
                    assert.isDefined(userInfo, `User with user.id "${user.id}" was never registered!`);
                    console.log(userInfo, user)
                    assert.isDefined(user.name, 'user is missing "name" field!');
                    assert.isString(user.name, 'user.name MUST be of type STRING!');
                    assert.isNotEmpty(user.name, 'user.name MUST NOT be empty!');
                    assert.strictEqual(user.name, userInfo.name, 'user.name MUST be set to the registered name!');

                    assert.isDefined(user.displayName, 'user is missing "displayName" field!');
                    assert.isString(user.displayName, 'user.displayName MUST be of type STRING!');
                    assert.isNotEmpty(user.displayName, 'user.displayName MUST NOT be empty!');
                    assert.strictEqual(user.displayName, userInfo.displayName, 'user.displayName MUST be set to the registered displayName!');

                    assert.isDefined(user.icon, 'user is missing "icon" field!');
                    assert.isString(user.icon, 'user.icon MUST be of type STRING!');
                    assert.isNotEmpty(user.icon, 'user.icon MUST NOT be empty!');
                    assert.strictEqual(user.icon, userInfo.icon, 'user.icon MUST be set to the registered icon!');
                }
            })
    })

    it(`P-4
    
        FOR AUTHENTICATORS WITH DISPLAY

        Send three valid CTAP2 authenticatorMakeCredential(0x01) message, "options" containg an "rk" option set to true, wait for the responses, and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code.

        Send three CTAP2 authenticatorGetAssertion(0x02) messages, with no allowList presented, asking using in a random order to select credentials, wait for the response and check that Authenticator returns CTAP1_ERR_SUCCESS(0x00) error code. Check that response contains "numberOfCredentials" field that is of type Number and is set to 1.

    `, function() {
        this.timeout(60000);

        if(!authenticatorWithDisplay)
            this.skip()

        let users = [];
        let userSelectionIndexes = generateListOfRandomIndexes(3);

        let makeCredStruct = generateGoodCTAP2MakeCreditentials();
        let options = {'rk': true}
        let rp = makeCredStruct.rp;
        let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)

        users.push(makeCredStruct.user);

        let checkResponseIsCorrect = (ctap2Response, userInfo) => {
            assert.strictEqual(ctap2Response.statusCode, CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS, `Expected authenticator to succeed with CTAP1_ERR_SUCCESS(${hexifyInt(CTAP_ERROR_CODES.CTAP1_ERR_SUCCESS)}). Got ${CTAP_ERROR_CODES[ctap2Response.statusCode]}(${hexifyInt(ctap2Response.statusCode)})`);

            let cborResponse       = ctap2Response.cborResponse;
            let cborResponseStruct = ctap2Response.cborResponseStruct;

            if(cborResponse[GetAssertionRespKeys.numberOfCredentials]) {
                assert.strictEqual(cborResponse[GetAssertionRespKeys.numberOfCredentials], 1, 'For devices with the display, numberOfCredentials must be set to 1');
            }

            if(cborResponse[GetAssertionRespKeys.credential]) {
                assert.isObject(cborResponse[GetAssertionRespKeys.credential], 'GetAssertion_Response.credential MUST be of type MAP!');

                assert.strictEqual(type(cborResponseStruct[GetAssertionRespKeys.credential].id), 'Uint8Array', 'credential.id MUST be of type BYTE STRING!');
                assert.isAbove(cborResponseStruct[GetAssertionRespKeys.credential].id.byteLength, 0, 'credential.id MUST not be empty!');

                assert.isString(cborResponse[GetAssertionRespKeys.credential].type, 'credential.id MUST be of type STRING!');
                assert.strictEqual(cborResponse[GetAssertionRespKeys.credential].type, 'public-key', 'credential.type MUST strictly equal to "public-key"!');
            }

            let user = cborResponse[GetAssertionRespKeys.user];
            assert.isDefined(user, 'GetAssertion_Response missing "user" field! For Device Resident Key credential, "user" field MUST be present.')
            assert.isObject(user, 'GetAssertion_Response.user MUST be of type MAP!');

            assert.isDefined(user.id, 'user missing "id" field!');
            assert.strictEqual(type(cborResponseStruct[GetAssertionRespKeys.user].id), 'Uint8Array', 'user.id MUST be of type BYTE STRING!');
            assert.strictEqual(user.id, hex.encode(userInfo.id), 'user.id MUST be set to the registered id!');

            if(user.name) {
                assert.isString(user.name, 'user.name MUST be of type STRING!');
                assert.isNotEmpty(user.name, 'user.name MUST NOT be empty!');
                assert.strictEqual(user.name, userInfo.name, 'user.name MUST be set to the registered name!');
            }

            if(user.displayName) {
                assert.isString(user.displayName, 'user.displayName MUST be of type STRING!');
                assert.isNotEmpty(user.displayName, 'user.displayName MUST NOT be empty!');
                assert.strictEqual(user.displayName, userInfo.displayName, 'user.displayName MUST be set to the registered displayName!');
            }

            if(user.icon) {
                assert.isString(user.icon, 'user.icon MUST be of type STRING!');
                assert.isNotEmpty(user.icon, 'user.icon MUST NOT be empty!');
                assert.strictEqual(user.icon, userInfo.icon, 'user.icon MUST be set to the registered icon!');
            }
        }

        let selectedIndex    = undefined;
        let selectedUserInfo = undefined;
        return sendValidCTAP_CBOR(commandBuffer)
            .then((ctap2Response) => {
                let makeCredStruct = generateGoodCTAP2MakeCreditentials();
                let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)

                users.push(makeCredStruct.user);

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((ctap2Response) => {
                let makeCredStruct = generateGoodCTAP2MakeCreditentials();
                let commandBuffer  = generateMakeCreditentialsReqCBOR(makeCredStruct.clientDataHash, rp, makeCredStruct.user, makeCredStruct.pubKeyCredParams, undefined, undefined, options)
    
                users.push(makeCredStruct.user);

                return sendValidCTAP_CBOR(commandBuffer)
            })
            .then((response) => {
                let goodAssertion = generateGoodCTAP2GetAssertion(origin);
                let getAssertionBuffer = generateGetAssertionReqCBOR(rp.id, goodAssertion.clientDataHash)

                selectedIndex    = userSelectionIndexes.pop();
                selectedUserInfo = users[selectedIndex];
                alert(`Please select credential for ${selectedUserInfo.displayName}!`);

                return sendValidCTAP_CBOR(getAssertionBuffer)
            })
            .then((ctap2Response) => {
                checkResponseIsCorrect(ctap2Response, selectedUserInfo)
                
                let goodAssertion = generateGoodCTAP2GetAssertion(origin);
                let getAssertionBuffer = generateGetAssertionReqCBOR(rp.id, goodAssertion.clientDataHash)

                selectedIndex    = userSelectionIndexes.pop();
                selectedUserInfo = users[selectedIndex];
                alert(`Please select credential for ${selectedUserInfo.displayName}!`);

                return sendValidCTAP_CBOR(getAssertionBuffer)
            })
            .then((ctap2Response) => {
                checkResponseIsCorrect(ctap2Response, selectedUserInfo)
                
                let goodAssertion = generateGoodCTAP2GetAssertion(origin);
                let getAssertionBuffer = generateGetAssertionReqCBOR(rp.id, goodAssertion.clientDataHash)

                selectedIndex    = userSelectionIndexes.pop();
                selectedUserInfo = users[selectedIndex];
                alert(`Please select credential for ${selectedUserInfo.displayName}!`);

                return sendValidCTAP_CBOR(getAssertionBuffer)
            })
            .then((ctap2Response) => {
                checkResponseIsCorrect(ctap2Response, selectedUserInfo)
            })
    })
})