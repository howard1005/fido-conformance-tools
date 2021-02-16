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

    let ui = new window.UAF.UAFUI();

    /**
     * UAF Operation to ASM Command
     * @type {Object}
     */
    let UAFOPToASMCMD = {
        'Reg'  : 'Register',
        'Auth' : 'Authenticate',
        'Dereg': 'Deregister'
    }

    /**
     * Maps OP to Schema request type
     * @type {Object}
     */
    let SchemeRequestMapping = {
        'Reg'  : 'RegistrationRequest',
        'Auth' : 'AuthenticationRequest',
        'Dereg': 'DeregistrationRequest'
    }

    class UAFClient {
        constructor(facetID, params, modifierParams) {
            this.attestationType    = params.attestationType;
            this.userSelectCallback = params.userSelectionCallback;
            this.params  = params;
            this.facetID = facetID;
            this.vault   = new window.UAF.KeyEnclave(params, modifierParams)
            params.vault = this.vault;
            this.asm     = new window.UAF.UAFASM(facetID, params, modifierParams);
            this.modifierParams    = modifierParams
            this.metadataStatement = params.metadataStatement
            this.appID = undefined;
        }

        processUAFMessage(message) {
            return new Promise((resolve, reject) => {
                    /* 5.
                     * Obtain FacetID of the requesting Application. If the AppID is missing or empty, set the AppID to the FacetID.
                     */
                    // if(!message.header.appID)
                    //     message.header.appID = facetID;
                    
                    /* 3. If a mandatory field in UAF message is not present or a field doesn't correspond to its type and value - reject the operation */
                    // let scheme = {
                    //     allOf : [{ 
                    //         '$ref' : `Requests.scheme.json#/definitions/${SchemeRequestMapping[message.header.op]}`
                    //     }]
                    // }
                    // if(!validateDataAgainstScheme(message, scheme).valid)
                    //     reject(new Error(INTERFACE_STATUS_CODES_TO_INT['PROTOCOL_ERROR']))

                    resolve()

                })
                .then(() => {
                    /* 5.
                     * Obtain FacetID of the requesting Application. If the AppID is missing or empty, set the AppID to the FacetID.
                     * Verify that the FacetID is authorized for the AppID according to the algorithms in [FIDOAppIDAndFacets].
                     * If the FacetID of the requesting Application is not authorized, reject the operation
                     */
                    // return VerifyFacets(message.header.appID, this.facetID)
                })
                .then(() => {
                    if(message.header.appID === undefined || message.header.appID === null || message.header.appID === '')
                        this.appID = this.facetID;
                    else
                        this.appID = message.header.appID;

                    /**
                     * Generating fcp
                     */
                    let FinalChallengeParams = {
                        'facetID': this.facetID,
                        'appID': this.appID,
                        'challenge': message.challenge,
                        'channelBinding': {}
                    }

                    /**
                     * Skip facetID. Ref: Reg-Resp-4-F-5/6
                     */
                    if(this.modifierParams && this.modifierParams.context === message.header.op && this.modifierParams.fcParamsCustomFacetIDEnabled) {
                        FinalChallengeParams.facetID = this.modifierParams.fcParamsCustomFacetID;
                    }

                    /**
                     * Skip appID. Ref: Reg-Resp-4-F-1/2
                     */
                    if(this.modifierParams && this.modifierParams.context === message.header.op && this.modifierParams.fcParamsCustomAppIDEnabled) {
                        FinalChallengeParams.appID = this.modifierParams.fcParamsCustomAppID;
                    }

                    /**
                     * Skip challenge. Ref: Reg-Resp-4-F-3/4
                     */
                    if(this.modifierParams && this.modifierParams.context === message.header.op && this.modifierParams.fcParamsCustomChallengeEnabled)
                        FinalChallengeParams.challenge = this.modifierParams.fcParamsCustomChallenge;

                    /**
                     * Skip channelBinding. Ref: Reg-Resp-4-F-7/8
                     */
                    if(this.modifierParams && this.modifierParams.context === message.header.op && this.modifierParams.fcParamsCustomChannelBindingEnabled)
                        FinalChallengeParams.channelBinding = this.modifierParams.fcParamsCustomChannelBinding;

                    let fcp = UTF8ToB64URL(JSON.stringify(FinalChallengeParams));
                    let request = UAFOPToASMCMD[message.header.op];

                    return this.makeASMRequest(request, fcp, message);
                })
                .catch((error) => {
                    console.error(error.message)
                    throw new Error(error.message)
                })
        }

        makeASMRequest(request, fcp, message) {
            let ASMRequest = {};

            if (['Register', 'Authenticate', 'Deregister', 'GetInfo', 'OpenSettings', 'GetRegistrations'].indexOf(request) !== -1) {

                ASMRequest = {
                    'asmVersion' : this.params.upv,
                    'authenticatorIndex': 42
                }

                switch(request) {
                    case 'Register':
                        ASMRequest.requestType = 'Register';
                        ASMRequest.args = {
                            'appID'          : this.appID,
                            'username'       : message.username,
                            'finalChallenge' : fcp,
                            'attestationType': TAG_DIR_TO_INT[this.attestationType]
                        }

                        return this.asm.processRequest(ASMRequest)
                            .then((RegisterOut) => {
                                let RegistrationResponse = {
                                    'header': message.header,
                                    'fcParams': fcp,
                                    'assertions': []
                                }

                                RegistrationResponse.assertions.push(RegisterOut);

                                return RegistrationResponse
                            })
                    break

                    case 'Authenticate': 
                        ASMRequest.requestType = 'Authenticate';
                        ASMRequest.args = {
                            'appID': this.appID,
                            'keyIDs': [],
                            'finalChallenge': fcp,
                            'transaction': message.transaction
                        }

                        return Promise.resolve({})
                            .then(() => {

                                if(!this.metadataStatement.isSecondFactorOnly) {
                                    /* Select first user in the list */
                                    return this.vault.getUsers(this.appID)
                                        .then((users) => {
                                            return ui.selectKeyHandle(users, this.params.selectKeyHandleCallback)
                                        })
                                        .then((response) => {
                                            if(response)
                                                return response.keyID
                                            else
                                                return ErrorPromise(INTERFACE_STATUS_CODES_TO_INT['USER_CANCELLED'])
                                        })
                                } else {
                                    for(let policyStatement of message.policy.accepted) {
                                        for(let matchCriteria of policyStatement) {
                                            if(matchCriteria.aaid && matchCriteria.add.indexOf(this.metadataStatement.aaid) !== -1) {
                                                if(matchCriteria.keyIDs) {
                                                    for(let keyID of matchCriteria.keyIDs) {
                                                        if(this.vault.keyIDExists(keyID)) {
                                                            return keyID
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    return ErrorPromise(INTERFACE_STATUS_CODES_TO_INT['PROTOCOL_ERROR'])
                                }
                            })
                            .then((keyID) => {
                                ASMRequest.args.keyIDs.push(keyID);
                                return this.asm.processRequest(ASMRequest)
                            })
                            .then((AuthenticateOut) => {
                                let AuthenticationResponse = {
                                    'header': message.header,
                                    'fcParams': fcp,
                                    'assertions': []
                                }

                                AuthenticationResponse.assertions.push(AuthenticateOut);

                                return AuthenticationResponse
                            })
                    break

                    case 'Deregister':
                        ASMRequest.requestType = 'Deregister';

                        let requests = [];

                        for(let authenticator of message.authenticators) {
                            ASMRequest.args = {
                                'appID': this.appID,
                                'keyID': authenticator.keyID
                            }

                            requests.push(this.asm.processRequest(ASMRequest));
                        }

                        return Promise.all(requests.map(reflectPromise))
                                .then(() => {
                                    return undefined
                                })
                    break

                    case 'GetInfo':
                        ASMRequest.requestType = 'GetInfo';
                        return this.asm.processRequest(ASMRequest);
                    break

                    case 'OpenSettings':
                        ASMRequest.requestType = 'OpenSettings';
                        return this.asm.processRequest(ASMRequest);
                    break

                    case 'GetRegistrations':
                        ASMRequest.requestType = 'GetRegistrations';
                        return this.asm.processRequest(ASMRequest);
                    break
                }

            } else 
                return ErrorPromise(INTERFACE_STATUS_CODES_TO_INT['PROTOCOL_ERROR'])
        }
    }

    window.UAF.UAFClient = UAFClient;

})()
