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
     * Verifies validity of a given authrParams
     * @param  {Object}
     */
    let verifyAuthrParams = (authrParams) => {

        /* Ensure that all fields are string value */
        for(let key in authrParams)
            if(type(authrParams[key]) !== 'String' && type(authrParams[key]) !== 'Function' && key !== 'metadataStatement')
                throw new Error(`Field ${key} must be type of string!`);

        if(authrParams.aaid.length !== 9)
            throw new Error('AAID must be nine characters long, in format 1234#1234');

        if(type(authrParams.selectKeyHandleCallback) !== 'Function')
            throw new Error('selectKeyHandleCallback callback is missing, or it\'s not a function!');

        if(type(authrParams.confirmTransactionContentCallback) !== 'Function')
            throw new Error('confirmTransactionContentCallback callback is missing, or it\'s not a function!');

        if(type(authrParams.metadataStatement) !== 'Object')
            throw new Error('metadataStatement is missing!')
    }

    class UAFClientAPI {
        constructor(facetID, authrParams, modifierParams) {
            /**
             * Available modifiers
             * 
             * skipPublicKey
             * skipKeyID
             * skipAAID
             * skipAuthenticatorVersion
             * skipSignatureCounter
             * skipCertificate
             * 
             * reuseKeyPair
             * signSurrogateWithBatchKey
             * metadataStatement
             * customRegistrationCounter
             * 
             * FCHash
             * FCHashFunction
             * 
             * fcParamsCustomFacetID
             * fcParamsCustomAppID
             * fcParamsCustomChallenge
             * fcParamsCustomChannelBinding
             * 
             * fcParamsCustomFacetIDEnabled
             * fcParamsCustomAppIDEnabled
             * fcParamsCustomChallengeEnabled
             * fcParamsCustomChannelBindingEnabled
             * 
             */
    
            /* Verify authrParams */
            verifyAuthrParams(authrParams);

            /**
             * Injecting bad metadata statements
             */
            if(modifierParams && modifierParams.metadataStatement)
                authrParams.metadataStatement = modifierParams.metadataStatement

            authrParams = Object.assign({}, authrParams);
            authrParams.authenticationAlgorithm = ALG_DIR[authrParams.metadataStatement.authenticationAlgorithm]
            authrParams.publicKeyAlgAndEncoding = ALG_DIR[authrParams.metadataStatement.publicKeyAlgAndEncoding]
            authrParams.attestationType         = TAG_DIR[authrParams.metadataStatement.attestationTypes[0]]
            authrParams.aaid                    = authrParams.metadataStatement.aaid;

            /**
             * Setting protocol version
             * @type {Object}
             */
            authrParams.upv = {
                'major': 1,
                'minor': 0
            }

            this.uafClient = new window.UAF.UAFClient(facetID, authrParams, modifierParams);
        }

        discover() {

        }

        checkPolicy() {}

        processUAFOperation(UAFMessage, completionCallback, errorCallback) {
            let additionalData = UAFMessage.additionalData;
            let messages = tryDecodeJSON(UAFMessage.uafProtocolMessage);

            /**
             * completionCallback must be presented
             */
            if(!completionCallback || type(completionCallback) !== 'Function') {
                console.error('completionCallback is missing!');
                errorCallback(INTERFACE_STATUS_CODES_TO_INT['PROTOCOL_ERROR'])
                return
            }

            /**
             * errorCallback must be presented
             */
            if(!errorCallback || type(errorCallback) !== 'Function') {
                console.error('errorCallback is missing!');
                errorCallback(INTERFACE_STATUS_CODES_TO_INT['PROTOCOL_ERROR'])
                return
            }

            /**
             * Searching for UAF Message with protocol version v1.0
             */
            let selectedMessage;
            for(let message of messages) {
                if(verifyProtocolVersion(message.header.upv)){
                    selectedMessage = message;
                    break
                }
            }


            if(!selectedMessage){
                errorCallback(INTERFACE_STATUS_CODES_TO_INT['UNSUPPORTED_VERSION']);
                return
            }

            this.uafClient.processUAFMessage(selectedMessage)
                .then((response) => {
                    let uafProtocolMessage;

                    /**
                     * If dereg, no response given
                     */
                    if(response) {
                        uafProtocolMessage = JSON.stringify([response])
                    } else {
                        console.error('Client returned no data!');
                        error.callback(INTERFACE_STATUS_CODES_TO_INT['UNKNOWN_ERROR'])
                    }

                    completionCallback({
                        uafProtocolMessage,
                        additionalData
                    })
                })
                .catch((error) => {
                    console.error('Error code: ' + error.message, '\nError ID: ' + INTERFACE_STATUS_CODES_TO_INT[error.message], '\nError STACK: ' + error.toString());
                    errorCallback(error.message)
                })
        }

        notifyUAFResult() {
            /* Do nothing, lol */
        }
    }

    window.UAF.UAFClientAPI = UAFClientAPI;

})()
