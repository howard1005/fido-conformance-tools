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

(function() {

    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    });

    class UAFASM {
        constructor(facetID, params, modifierParams) {
            this.facetID = facetID;
            this.vault   = params.vault;
            this.modifierParams = modifierParams;
            this.authenticator = new window.UAF.UAFAuthenticator(params, modifierParams);
        }

        processRequest(request) {
            let structure;

            switch(request.requestType) {

                /**
                 * Ref: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-asm-api-v1.0-ps-20141208.html#detailed-description-for-processing-the-register-request
                 */
                case 'Register':
                    /* 6. Create a TAG_UAFV1_REGISTER_CMD structure and pass it to the authenticator */
                    structure = {
                        'TAG_UAFV1_REGISTER_CMD': {
                            'TAG_AUTHENTICATOR_INDEX': {
                                'AuthenticatorIndex': new Uint8Array([request.authenticatorIndex])
                            },
                            'TAG_APPID': {
                                'AppID': stringToArrayBuffer(request.args.appID)
                            },
                            'TAG_FINAL_CHALLENGE_HASH': {
                                'FinalChallenge': ''
                            },
                            'TAG_USERNAME': {
                                'Username': stringToArrayBuffer(request.args.username)
                            },
                            'TAG_ATTESTATION_TYPE': {
                                'AttestationType': new Uint16Array([request.args.attestationType])
                            }
                        }
                    }

                    return Promise.all([
                        /* 4. Construct KHAccessToken */
                        this.vault.generateKHAccessToken(request.args.appID),

                        /* 5. Hash the provided RegisterIn.finalChallenge using the authenticator-specific hash function (FinalChallengeHash) */
                        this.vault.hash(stringToArrayBuffer(request.args.finalChallenge))
                    ])  
                        .then((result) => {
                            /**
                             * Replacing FCHash with a custom arraybuffer. Ref: Reg-Resp-7-F-18
                             */
                            if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.FCHash)
                                result[1] = this.modifierParams.FCHash;

                            /**
                             * Hashing fcParams with a custom hash function. Ref: Reg-Resp-7-F-19
                             */
                            if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.FCHashFunction)
                                result[1] = crypto.subtle
                                    .digest(this.modifierParams.FCHashFunction, stringToArrayBuffer(request.args.finalChallenge))

                            return Promise.all(result)
                        })
                        .then((result) => {
                            let KHAccessToken = result[0];
                            let FinalChallengeHash = result[1];

                            structure.TAG_UAFV1_REGISTER_CMD.TAG_KEYHANDLE_ACCESS_TOKEN = {
                                'KHAccessToken': KHAccessToken
                            }

                            structure.TAG_UAFV1_REGISTER_CMD.TAG_FINAL_CHALLENGE_HASH = {
                                'FinalChallenge': FinalChallengeHash
                            }

                            let request = tlv.generator.generateWithSchema(window.UAF.TLVSchemas.REGISTER_CMD_SCHEMA, structure);
                            let requestB64URL = base64url.encode(request);

                            /* 7. Invoke the command and receive the response */
                            return this.authenticator.processRequest(requestB64URL)
                        })
                        .then((CMD_RESPONSE) => {
                            /* 8. Parse TAG_UAFV1_REGISTER_CMD_RESP */
                            let RESPONSE_BUFFER = base64url.decode(CMD_RESPONSE);
                            let RESPONSE = tlv.parser.parse(RESPONSE_BUFFER);
                            let STATUS_CODE = RESPONSE.TAG_UAFV1_REGISTER_CMD_RESPONSE.TAG_STATUS_CODE;

                            
                            if(STATUS_CODE === 'UAF_CMD_STATUS_OK') {
                                let assertionBuffer = tlv.parser.searchTAG(RESPONSE_BUFFER, 'TAG_UAFV1_REG_ASSERTION')

                                /* 10. Create a RegisterOut object */
                                let registerOut = {
                                    'assertionScheme': 'UAFV1TLV',
                                    'assertion': base64url.encode(assertionBuffer)
                                }
                                
                                return registerOut
                            }
                            
                            throw new Error(STATUS_CODE)
                        })

                break

                /**
                 * Ref: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-asm-api-v1.0-ps-20141208.html#detailed-description-for-processing-the-authenticate-request
                 */
                case 'Authenticate':
                    /* Create TAG_UAFV1_SIGN_CMD structure and pass it to the authenticator */
                    structure = {
                        'TAG_UAFV1_SIGN_CMD': {
                            'TAG_AUTHENTICATOR_INDEX': {
                                'AuthenticatorIndex': new Uint8Array([request.authenticatorIndex])
                            },
                            'TAG_APPID':{
                                'AppID': stringToArrayBuffer(request.args.appID)
                            },
                            'TAG_FINAL_CHALLENGE_HASH':{
                                'FinalChallenge': ''
                            }
                        }
                    }

                    if(request.args.transaction && request.args.transaction.length) {
                        /* TODO: Testing for different types of transaction content */
                        /* 8.1.B If multiple transactions are provided, select the one that best matches the current display characteristics */
                        structure.TAG_UAFV1_SIGN_CMD.TAG_TRANSACTION_CONTENT = {
                            /* 8.1.C Decode the base64url encoded AuthenticateIn.Transaction.content before passing it to the authenticator */
                            'TransactionContent': base64url.decode(request.args.transaction[0].content)
                        }
                    } else {
                        structure.TAG_UAFV1_SIGN_CMD.TAG_TRANSACTION_CONTENT = {
                            /* 8.1.C Decode the base64url encoded AuthenticateIn.Transaction.content before passing it to the authenticator */
                            'TransactionContent': new Uint8Array()
                        }
                    }

                    if(request.args.keyIDs && request.args.keyIDs.length) {
                        structure.TAG_UAFV1_SIGN_CMD.TAG_KEYHANDLE = {
                            'KeyHandle': base64url.decode(request.args.keyIDs[0])
                        }
                    }

                    return Promise.all([
                        /* 4. Construct KHAccessToken (see section KHAccessToken for more details) */
                        this.vault.generateKHAccessToken(request.args.appID),

                        /* 5. Hash the provided AuthenticateIn.finalChallenge using an authenticator-specific hash function (FinalChallengeHash) */
                        this.vault.hash(stringToArrayBuffer(request.args.finalChallenge))

                    ])
                        .then((result) => {
                            /**
                             * Replacing FCHash with a custom arraybuffer. Ref: Reg-Resp-7-F-18
                             */
                            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.FCHash)
                                result[1] = this.modifierParams.FCHash;

                            /**
                             * Hashing fcParams with a custom hash function. Ref: Reg-Resp-7-F-19
                             */
                            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.FCHashFunction)
                                result[1] = crypto.subtle
                                    .digest(this.modifierParams.FCHashFunction, stringToArrayBuffer(request.args.finalChallenge))

                            return Promise.all(result)
                        })
                        .then((result) => {
                            let KHAccessToken = result[0];
                            let FinalChallengeHash = result[1];

                            structure.TAG_UAFV1_SIGN_CMD.TAG_KEYHANDLE_ACCESS_TOKEN = {
                                'KHAccessToken': KHAccessToken
                            }

                            structure.TAG_UAFV1_SIGN_CMD.TAG_FINAL_CHALLENGE_HASH = {
                                'FinalChallenge': FinalChallengeHash
                            }

                            let request = tlv.generator.generateWithSchema(window.UAF.TLVSchemas.SIGN_CMD_SCHEMA, structure);
                            let requestB64URL = base64url.encode(request);

                            /* 9. Invoke the command and receive the response */
                            return this.authenticator.processRequest(requestB64URL)
                        })
                        .then((CMD_RESPONSE) => {
                            /* 10. Parse TAG_UAFV1_SIGN_CMD_RESP */
                            let RESPONSE_BUFFER = base64url.decode(CMD_RESPONSE);
                            let RESPONSE = tlv.parser.parse(RESPONSE_BUFFER);
                            let STATUS_CODE = RESPONSE.TAG_UAFV1_SIGN_CMD_RESPONSE.TAG_STATUS_CODE;

                            if(STATUS_CODE === 'UAF_CMD_STATUS_OK') {

                                let assertionBuffer = tlv.parser.searchTAG(RESPONSE_BUFFER, 'TAG_UAFV1_AUTH_ASSERTION');

                                /* 11. Create the AuthenticateOut object */
                                let AuthenticateOut = {
                                    /* 11.1 Set AuthenticateOut.assertionScheme as AuthenticatorInfo.assertionScheme */ 
                                    'assertionScheme': 'UAFV1TLV',
                                    'assertion': base64url.encode(assertionBuffer)
                                }

                                return AuthenticateOut
                            }

                            throw new Error(STATUS_CODE)
                        })

                break

                /**
                 * Ref: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-asm-api-v1.0-ps-20141208.html#detailed-description-for-processing-the-deregister-request
                 */
                case 'Deregister':
                    /* 4. Create the TAG_UAFV1_DEREGISTER_CMD structure, copy KHAccessToken, DeregisterIn.keyID and pass it to the authenticator. */
                    structure = {
                        'TAG_UAFV1_DEREGISTER_CMD': {
                            'TAG_AUTHENTICATOR_INDEX': {
                                'AuthenticatorIndex': new Uint8Array([request.authenticatorIndex])
                            },
                            'TAG_APPID': {
                                'AppID': stringToArrayBuffer(request.args.appID)
                            },
                            'TAG_KEYID': {
                                'KeyID': base64url.decode(request.args.keyID)
                            },
                            'TAG_KEYHANDLE_ACCESS_TOKEN': {
                                'KHAccessToken': ''
                            }
                        }
                    }

                    /* 2. Construct KHAccessToken (see section KHAccessToken for more details) */
                    return this.vault.generateKHAccessToken(request.args.appID)
                        .then((KHAccessToken) => {
                            structure.TAG_UAFV1_DEREGISTER_CMD.TAG_KEYHANDLE_ACCESS_TOKEN = {
                                'KHAccessToken': KHAccessToken
                            }

                            let request = tlv.generator.generateWithSchema(window.UAF.TLVSchemas.DEREGISTER_CMD_SCHEMA, structure);
                            let requestB64URL = base64url.encode(request);

                            /* 4. Invoke the command and receive the response */
                            return this.authenticator.processRequest(requestB64URL)
                        })
                        .then((response) => {
                            let responseBuffer = base64url.decode(response);
                            let responseStruct = tlv.parser.parse(responseBuffer);
                            let responseCode   = responseStruct.TAG_UAFV1_DEREGISTER_CMD_RESPONSE.TAG_STATUS_CODE;
                            if(responseCode === 'UAF_CMD_STATUS_OK')
                                return true
                            else
                                throw new Error(responseCode)
                        })

                break
            }
        }
    }

    window.UAF.UAFASM = UAFASM;

})()
