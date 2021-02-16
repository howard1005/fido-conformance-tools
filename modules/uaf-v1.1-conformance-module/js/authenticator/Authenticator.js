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

    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    })

    let ui  = new window.UAF.UAFUI();

    /**
     * Authentication Mode indicating whether user explicitly verified or not and indicating if there is a transaction content or not.
     * 0x01 means that user has been explicitly verified
     * 0x02 means that transaction content has been shown on the display and user confirmed it by explicitly verifying with authenticator
     * @type {Object}
     */
    let AuthenticationModes = {
        'ExplicitlyVerified': 0x01,
        'TransactionDisplayVerified': 0x02
    }

    class UAFAuthenticator {
        constructor(params, modifierParams) {
            this.RegCounter  = 0;
            this.SignCounter = 0;
            this.version = 1;
            this.params  = params;
            this.metadataStatement = params.metadataStatement;
            this.vault   = params.vault;
            this.modifierParams = modifierParams;

            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.customSignCounter)
                this.SignCounter = this.modifierParams.customSignCounter;
        }

        /**
         * Generates registration assertion
         * Ref: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-authnr-cmds-v1.0-ps-20141208.html#register-command
         * @param  {Object} request - TAG_UAFV1_REGISTER_CMD
         * @return {Promise}
         */
        __Register(request) {
            let KHAccessToken = request.TAG_KEYHANDLE_ACCESS_TOKEN;
            let username      = request.TAG_USERNAME;

            /**
             * If the RegCounter is implemented: ensure that it is increased by any registration
             */
            this.RegCounter++;

            /* 4. Make sure that Command.TAG_ATTESTATION_TYPE is supported. If not - return UAF_CMD_STATUS_ATTESTATION_NOT_SUPPORTED */
            if(request.TAG_ATTESTATION_TYPE === this.params.attestationType)
                /* 5. Generate a new key pair (UAuth.pub/UAuth.priv) */
                return this.vault.generateNewKeyPair(KHAccessToken, username)
                    /* Exporting public key */
                    .then((keyHandleIDBuffer) => {
                        return Promise.all([
                            this.vault.exportPublicKey(keyHandleIDBuffer),
                            keyHandleIDBuffer
                        ])
                    })

                    /* Generating assertion */
                    .then((result) => {
                        
                        let publicKeyBuffer = result[0];
                        /**
                         * Empty public key.
                         */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptyPublicKey)
                            publicKeyBuffer = new Uint8Array();

                        
                        let keyHandleIDBuffer = result[1];
                        let KeyHandleID       = base64url.encode(keyHandleIDBuffer);
                        /**
                         * Empty keyID.
                         */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptyKeyID)
                            keyHandleIDBuffer = new Uint8Array();


                        let AAIDBuffer = stringToArrayBuffer(this.params.aaid);
                        /**
                         * Empty AAID.
                         */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptyAAID)
                            AAIDBuffer = new Uint8Array();

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.customAAID)
                            AAIDBuffer = stringToArrayBuffer(this.modifierParams.customAAID)


                        let AuthenticatorVersion = new Uint16Array([this.version])
                        /**
                         * Empty AuthenticatorVersion.
                         */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptyAuthenticatorVersion)
                            AuthenticatorVersion = new Uint8Array();


                        let SignatureCounter = new Uint32Array([this.SignCounter])
                        /**
                         * Empty Signature.
                         */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptySignatureCounter)
                            SignatureCounter = new Uint8Array();


                        let RegistrationCounter = new Uint32Array([this.RegCounter]);
                        /**
                         * Set registration counter to specific value.
                         */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.customRegistrationCounter)
                            RegistrationCounter = new Uint32Array([this.modifierParams.customRegistrationCounter])

                        let finalChallengeBuffer = base64url.decode(request.TAG_FINAL_CHALLENGE_HASH);

                        /* 8. Create TAG_UAFV1_KRD structure */
                        let KRD = {
                            'TAG_UAFV1_KRD': {
                                'TAG_AAID': {
                                    'AAID': AAIDBuffer
                                },
                                'TAG_ASSERTION_INFO': {
                                    'AuthenticatorVersion'   : AuthenticatorVersion,
                                    'AuthenticationMode'     : new Uint8Array([AuthenticationModes['ExplicitlyVerified']]),
                                    'SignatureAlgAndEncoding': new Uint16Array([ALG_DIR_TO_INT[this.params.authenticationAlgorithm]]),
                                    'PublicKeyAlgAndEncoding': new Uint16Array([ALG_DIR_TO_INT[this.params.publicKeyAlgAndEncoding]])
                                },
                                'TAG_FINAL_CHALLENGE_HASH': {
                                    'FinalChallenge': finalChallengeBuffer
                                },
                                'TAG_KEYID': {
                                    'KeyID': keyHandleIDBuffer
                                },
                                'TAG_COUNTERS': {
                                    'SignCounter' : SignatureCounter,
                                    'RegCounter'  : new Uint32Array([this.RegCounter]) 
                                },
                                'TAG_PUB_KEY': {
                                    'PublicKey': publicKeyBuffer
                                }
                            }
                        }

                    /* Wrong data section */
                        /**
                         * Counters
                         */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.badCounters)
                            KRD.TAG_UAFV1_KRD.TAG_COUNTERS = mergeArrayBuffers(SignatureCounter, new Uint32Array([this.RegCounter]), new Uint32Array([0xdeadbeef]));

                        /**
                         * KeyID
                         */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.longKeyID)
                            KRD.TAG_UAFV1_KRD.TAG_KEYID.KeyID = mergeArrayBuffers(keyHandleIDBuffer, new Uint8Array([0x2A]));

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.shortKeyID)
                            KRD.TAG_UAFV1_KRD.TAG_KEYID.KeyID = keyHandleIDBuffer.slice(1);

                        /**
                         * AssertionInfo
                         */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.authenticationModeNotExplicitlyVefied)
                            KRD.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.AuthenticationMode = new Uint8Array([0x00]);

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.badSignatureAlgorithm)
                            KRD.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.SignatureAlgAndEncoding = new Uint16Array([0x00]);

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.badPublicKeyAlgorithm)
                            KRD.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.PublicKeyAlgAndEncoding = new Uint16Array([0x00]);

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.longAssertionInfo)
                            KRD.TAG_UAFV1_KRD.TAG_ASSERTION_INFO = mergeArrayBuffers(AuthenticatorVersion, new Uint8Array([AuthenticationModes['ExplicitlyVerified']]), new Uint16Array([ALG_DIR_TO_INT[this.params.authenticationAlgorithm]]), new Uint16Array([ALG_DIR_TO_INT[this.params.publicKeyAlgAndEncoding]]), new Uint32Array([0xdeadbeef]));

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.shortAssertionInfo)
                            KRD.TAG_UAFV1_KRD.TAG_ASSERTION_INFO = mergeArrayBuffers(new Uint8Array([AuthenticatorVersion]), new Uint8Array([AuthenticationModes['ExplicitlyVerified']]), new Uint16Array([ALG_DIR_TO_INT[this.params.authenticationAlgorithm]]));
                        
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptyAssertionInfo)
                            KRD.TAG_UAFV1_KRD.TAG_ASSERTION_INFO = new Uint8Array()

                    /*  Skip modifiers */
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipAAID)
                            KRD.TAG_UAFV1_KRD.TAG_AAID = undefined;
                        
                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipAssertionInfo)
                            KRD.TAG_UAFV1_KRD.TAG_ASSERTION_INFO = undefined;

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipFinalChallenge)
                            KRD.TAG_UAFV1_KRD.TAG_FINAL_CHALLENGE_HASH = undefined;

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipKeyID)
                            KRD.TAG_UAFV1_KRD.TAG_KEYID = undefined;

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipCounters)
                            KRD.TAG_UAFV1_KRD.TAG_COUNTERS = undefined;

                        if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipPublicKey)
                            KRD.TAG_UAFV1_KRD.TAG_PUB_KEY = undefined;


                        let KRDBuffer = tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.REGISTER_ASSERTION_SCHEMA_KRD, KRD)

                        return Promise.resolve({})
                            .then(() => {
                                
                                /* Basic full attestation */
                                if(request.TAG_ATTESTATION_TYPE == 'TAG_ATTESTATION_BASIC_FULL') {
                                    return Promise.all([
                                        /* Getting batch certificate */
                                        this.vault.getBatchCertificate(),

                                        /* 9. Perform attestation on TAG_UAFV1_KRD based on provided Command.AttestationType */
                                        this.vault.signWithBatchPrivateKey(KRDBuffer)
                                    ])
                                /* Basic surrogate attestation */
                                } else if(request.TAG_ATTESTATION_TYPE == 'TAG_ATTESTATION_BASIC_SURROGATE') {


                                    let signaturePromise;
                                    /**
                                     * Sign with batch key keyID.
                                     */
                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.signSurrogateWithBatchKey)
                                        signaturePromise = this.vault.signWithBatchPrivateKey(KRDBuffer);
                                    else
                                        signaturePromise = this.vault.signData(request.TAG_KEYHANDLE_ACCESS_TOKEN, KeyHandleID, KRDBuffer);

                                    return Promise.all([
                                        undefined,
                                        signaturePromise
                                    ])
                                }
                            })
                            .then((result) => {

                                let cert      = result[0];
                                let signature = result[1];

                                if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptyCertificate)
                                    cert = new Uint8Array();

                                /* 10. Create TAG_AUTHENTICATOR_ASSERTION */
                                let structure = {
                                    'TAG_UAFV1_REG_ASSERTION': {
                                        'TAG_UAFV1_KRD': KRD['TAG_UAFV1_KRD']
                                    }
                                }

                                /* Basic full attestation */
                                if(request.TAG_ATTESTATION_TYPE == 'TAG_ATTESTATION_BASIC_FULL') {
                                    structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_FULL'] = {
                                        'TAG_SIGNATURE': {
                                            'Signature': signature
                                        },
                                        'TAG_ATTESTATION_CERT': {
                                            'Certificate': cert
                                        }
                                    }

                                    /**
                                     * MODIFIERS
                                     */
                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipAttestation)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_FULL'] = undefined;

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptyAttestation)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_FULL'] = new Uint8Array();

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipSignature)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_FULL']['TAG_SIGNATURE'] = undefined

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptySignature)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_FULL']['TAG_SIGNATURE'] = new Uint8Array();

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.badSignature) {
                                        let signatureUint8Buffer = new Uint8Array(signature);
                                        signatureUint8Buffer[3] += 1;
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_FULL']['TAG_SIGNATURE'].Signature = signatureUint8Buffer
                                    }

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipCert)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_FULL']['TAG_ATTESTATION_CERT'] = undefined

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptyCert)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_FULL']['TAG_SIGNATURE'].Certificate = new Uint8Array();

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.badCert) {
                                        let certificateUint8Buffer = new Uint8Array(cert);
                                        certificateUint8Buffer[3] += 1;
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_FULL']['TAG_SIGNATURE'].Certificate = certificateUint8Buffer
                                    }
                                /* Basic surrogate attestation */
                                } else if(request.TAG_ATTESTATION_TYPE == 'TAG_ATTESTATION_BASIC_SURROGATE') {
                                    structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_SURROGATE'] = {
                                        'TAG_SIGNATURE': {
                                            'Signature': signature
                                        }
                                    }

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipAttestation)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_SURROGATE'] = undefined;

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptyAttestation)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_SURROGATE'] = new Uint8Array();

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.skipSignature)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_SURROGATE']['TAG_SIGNATURE'] = undefined

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.emptySignature)
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_SURROGATE']['TAG_SIGNATURE'].Signature = new Uint8Array();

                                    if(this.modifierParams && this.modifierParams.context === 'Reg' && this.modifierParams.badSignature) {
                                        let signatureUint8Buffer = new Uint8Array(signature);
                                        signatureUint8Buffer[3] += 1;
                                        structure['TAG_UAFV1_REG_ASSERTION']['TAG_ATTESTATION_BASIC_SURROGATE']['TAG_SIGNATURE'].Signature = signatureUint8Buffer
                                    }

                                }

                                return tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.REGISTER_ASSERTION_SCHEMA, structure)
                            })
                            .then((assertion) => {
                                let structure = {
                                    'TAG_UAFV1_REGISTER_CMD_RESPONSE': {
                                        'TAG_STATUS_CODE': {
                                            'StatusCode': new Uint16Array([CMD_STATUS_CODES_TO_INT['UAF_CMD_STATUS_OK']])
                                        },
                                        'TAG_AUTHENTICATOR_ASSERTION': {
                                            'Assertion': assertion
                                        }
                                    }
                                }

                                let TLVBUFFER = tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.REGISTER_CMD_RESPONSE_SCHEMA, structure);

                                /* 11. Return TAG_UAFV1_REGISTER_CMD_RESPONSE */
                                return base64url.encode(TLVBUFFER);
                            })
                            .catch((ERROR) => {
                                console.error(`AUTHR REG ERROR: ${ERROR.message}`)

                                let structure = {
                                    'TAG_UAFV1_REGISTER_CMD_RESPONSE': {
                                        'TAG_STATUS_CODE': {
                                            'StatusCode': new Uint16Array([CMD_STATUS_CODES_TO_INT[ERROR.message]])
                                        }
                                    }
                                }

                                let TLVBUFFER = tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.REGISTER_CMD_RESPONSE_SCHEMA, structure);

                                return base64url.encode(TLVBUFFER);
                            })
                    })
            else {
                /* 4. If not - return UAF_CMD_STATUS_ATTESTATION_NOT_SUPPORTED */
                return new Promise((resolve, reject) => {
                    console.error(`AUTHR REG ERROR: ${CMD_STATUS_CODES_TO_INT['UAF_CMD_STATUS_ATTESTATION_NOT_SUPPORTED']}`)

                    let structure = {
                        'TAG_UAFV1_REGISTER_CMD_RESPONSE': {
                            'TAG_STATUS_CODE': {
                                'StatusCode': new Uint16Array([CMD_STATUS_CODES_TO_INT['UAF_CMD_STATUS_ATTESTATION_NOT_SUPPORTED']])
                            }
                        }
                    }

                    let TLVBUFFER = tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.REGISTER_CMD_RESPONSE_SCHEMA, structure);

                    reject(base64url.encode(TLVBUFFER));
                })
            }
        }

        /**
         * Generates authentication assertion
         * Ref: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-authnr-cmds-v1.0-ps-20141208.html#command-description-2
         * @param  {Object} request - TAG_UAFV1_SIGN_CMD object
         * @return {Promise}
         */
        __Sign(request) {
            let KHAccessToken = request.TAG_KEYHANDLE_ACCESS_TOKEN;

            let AuthenticationMode = new Uint8Array([AuthenticationModes['ExplicitlyVerified']])
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.TCAuthenticationMode)
                AuthenticationMode = AuthenticationModes['TransactionDisplayVerified'];
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.badAuthenticationMode)
                AuthenticationMode = 0x00;
            /**
             * If the SignCounter is implemented: ensure that it is increased by any authentication / transaction confirmation operation
             */
            if(!(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.lockSignCounter))
                this.SignCounter++;
            
            let KeyHandleID       = request.TAG_KEYHANDLE;
            let keyHandleIDBuffer = base64url.decode(KeyHandleID);
            /**
             * Empty keyID.
             */
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptyKeyID)
                keyHandleIDBuffer = new Uint8Array();
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.shortKeyID)
                keyHandleIDBuffer = keyHandleIDBuffer.slice(1);
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.longKeyID)
                keyHandleIDBuffer = mergeArrayBuffers(keyHandleIDBuffer, new Uint8Array([0xde, 0xad]));



            let AAIDBuffer = stringToArrayBuffer(this.params.aaid);
            /**
             * Empty AAID.
             */
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptyAAID)
                AAIDBuffer = new Uint8Array();

            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.customAAID)
                AAIDBuffer = stringToArrayBuffer(this.modifierParams.customAAID);

            /**
             * Empty AAID. Ref: Auth-Resp-7-F-24
             */
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.customAAID)
                AAIDBuffer = stringToArrayBuffer(this.modifierParams.customAAID);


            let AuthenticatorVersion = new Uint16Array([this.version])
            /**
             * Empty AuthenticatorVersion.
             */
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptyAuthenticatorVersion)
                AuthenticatorVersion = new Uint8Array();


            let SignatureCounter = new Uint32Array([this.SignCounter])
            /**
             * Empty Signature.
             */
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptySignatureCounter)
                SignatureCounter = new Uint8Array();
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.badSignatureCounter)
                SignatureCounter = new Uint16Array([this.SignCounter]);

            let finalChallengeBuffer = base64url.decode(request.TAG_FINAL_CHALLENGE_HASH);
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptyFinalChallenge)
                finalChallengeBuffer = new Uint8Array();

            /* 8.1 Create TAG_UAFV1_SIGNED_DATA.. */
            let SIGNED_DATA_STRUCTURE = {
                'TAG_UAFV1_SIGNED_DATA': {
                    'TAG_AAID': {
                        'AAID': AAIDBuffer
                    },
                    'TAG_ASSERTION_INFO': {
                        'AuthenticatorVersion'   : AuthenticatorVersion,
                        /* 8.1 ..and set TAG_UAFV1_SIGNED_DATA.AuthenticationMode to 0x01 */
                        'AuthenticationMode'     : AuthenticationMode,
                        'SignatureAlgAndEncoding': new Uint16Array([ALG_DIR_TO_INT[this.params.authenticationAlgorithm]])
                    },
                    'TAG_AUTHENTICATOR_NONCE': {
                        'AuthrNonce': this.vault.randomBuffer(8)
                    },
                    'TAG_FINAL_CHALLENGE_HASH': {
                        'FinalChallenge': finalChallengeBuffer
                    },
                    'TAG_KEYID': {
                        'KeyID': keyHandleIDBuffer
                    },
                    'TAG_COUNTERS': {
                        'SignCounter': SignatureCounter
                    }
                }
            }

             /*  Skip modifiers */
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.skipAAID)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_AAID = undefined;
            
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.skipAssertionInfo)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO = undefined;

            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.longAssertionInfo)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO = mergeArrayBuffers(AuthenticatorVersion, new Uint8Array([AuthenticationModes['ExplicitlyVerified']]), new Uint16Array([ALG_DIR_TO_INT[this.params.authenticationAlgorithm]]), new Uint32Array([0x8BADF00D]));
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.shortAssertionInfo)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO = mergeArrayBuffers(AuthenticatorVersion, new Uint8Array([AuthenticationModes['ExplicitlyVerified']]));
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptyAssertionInfo)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO = new Uint8Array();
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.badSignatureAlgorithm)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.SignatureAlgAndEncoding = new Uint8Array([0x00]);

            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptyAssertionInfo)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO = new Uint8Array();

            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.skipAuthrNonce)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_AUTHENTICATOR_NONCE = undefined;
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptyAuthrNonce)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_AUTHENTICATOR_NONCE.AuthrNonce = new Uint8Array();
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.shortAuthrNonce)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_AUTHENTICATOR_NONCE.AuthrNonce = this.vault.randomBuffer(7);
            
            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.skipFinalChallenge)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_FINAL_CHALLENGE_HASH = undefined;

            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.skipKeyID)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_KEYID = undefined;

            if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.skipCounters)
                SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_COUNTERS = undefined;

            return ui.confirmTransaction(request.TAG_TRANSACTION_CONTENT, this.params.confirmTransactionContentCallback)
                .then(() => {
                    if(!request.TAG_TRANSACTION_CONTENT)
                        return new Uint8Array();

                    /* 8.2 If TransactionContent is not empty */
                    let transactionContentBuffer = base64url.decode(request.TAG_TRANSACTION_CONTENT);

                    if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.badTCAuthenticationMode)
                        /* 8.2.D.B Set TAG_UAFV1_SIGNED_DATA.AuthenticationMode to 0x02 */
                        SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.AuthenticationMode = new Uint8Array([AuthenticationModes['ExplicitlyVerified']]);
                    else
                        /* 8.2.D.B Set TAG_UAFV1_SIGNED_DATA.AuthenticationMode to 0x02 */
                        SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.AuthenticationMode = new Uint8Array([AuthenticationModes['TransactionDisplayVerified']]);

                    return this.vault.hash(transactionContentBuffer)
                })
                .then((transactionContentHash) => {
                    if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.TCHash)
                        transactionContentHash = this.modifierParams.TCHash;

                    if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptyTransactionContent)
                        transactionContentHash = new Uint8Array();

                    if(!(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.skipTransactionContent)) {
                        SIGNED_DATA_STRUCTURE['TAG_UAFV1_SIGNED_DATA']['TAG_TRANSACTION_CONTENT_HASH'] = {
                            'TCHash': new Uint8Array(transactionContentHash)
                        }
                    }

                    /* Generating TAG_UAFV1_SIGNED_DATA */
                    let SIGNED_DATA = tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA_SIGNED_DATA, SIGNED_DATA_STRUCTURE);

                    /* 8.3.B Sign TAG_UAFV1_SIGNED_DATA with UAuth.priv */
                    return this.vault.signData(request.TAG_KEYHANDLE_ACCESS_TOKEN, request.TAG_KEYHANDLE, SIGNED_DATA)
                })

                /* Generating final assertion */
                .then((signature) => {
                    if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.emptySignature)
                        signature = new Uint8Array();

                    if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.badSignature) {
                        signature = new Uint8Array(signature);
                        signature[3] = 0xde;
                        signature[4] = 0xad;
                        signature[5] = 0xbe;
                        signature[6] = 0xef;
                    }

                    /* 8.3 Create TAG_UAFV1_AUTH_ASSERTION */
                    let SIGN_ASSERTION_SCHEMA = {
                        'TAG_UAFV1_AUTH_ASSERTION': {
                            'TAG_UAFV1_SIGNED_DATA': SIGNED_DATA_STRUCTURE.TAG_UAFV1_SIGNED_DATA,
                            'TAG_SIGNATURE': {
                                'Signature': signature
                            }
                        }
                    }

                    if(this.modifierParams && this.modifierParams.context === 'Auth' && this.modifierParams.skipSignature)
                        SIGN_ASSERTION_SCHEMA['TAG_UAFV1_AUTH_ASSERTION']['TAG_SIGNATURE'] = undefined;

                    return tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, SIGN_ASSERTION_SCHEMA)
                })
                .then((assertion) => {
                    let structure = {
                        'TAG_UAFV1_SIGN_CMD_RESPONSE': {
                            'TAG_STATUS_CODE': {
                                'StatusCode': new Uint16Array([CMD_STATUS_CODES_TO_INT['UAF_CMD_STATUS_OK']])
                            },

                            /* 8.4 Put the entire TLV structure for TAG_UAFV1_AUTH_ASSERTION as the value of TAG_AUTHENTICATOR_ASSERTION */
                            'TAG_AUTHENTICATOR_ASSERTION': {
                                'Assertion': assertion
                            }
                        }
                    }

                    let TLVBUFFER = tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.SIGN_CMD_RESPONSE_SCHEMA, structure);

                    /* 8.5 Copy TAG_AUTHENTICATOR_ASSERTION into TAG_UAFV1_SIGN_CMD_RESPONSE and return */
                    return base64url.encode(TLVBUFFER);
                })
                .catch((ERROR) => {
                    console.error(`AUTHR SIGN ERROR: ${ERROR.message}`)
                    let structure = {
                        'TAG_UAFV1_SIGN_CMD_RESPONSE': {
                            'TAG_STATUS_CODE': {
                                'StatusCode': new Uint16Array([CMD_STATUS_CODES_TO_INT[ERROR.message]])
                            }
                        }
                    }

                    let TLVBUFFER = tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.SIGN_CMD_RESPONSE_SCHEMA, structure);

                    return base64url.encode(TLVBUFFER);
                })
        }

        /**
         * Performs deregistration operation
         * Ref: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-authnr-cmds-v1.0-ps-20141208.html#deregister-command
         * @param  {Object} request - TAG_UAFV1_DEREGISTER_CMD object
         * @return {Promise}
         */
        __Deregister(request) {
            let keyID         = request.TAG_KEYID;
            let KHAccessToken = request.TAG_KEYHANDLE_ACCESS_TOKEN;

            let structure = {
                'TAG_UAFV1_DEREGISTER_CMD_RESPONSE': {
                    'TAG_STATUS_CODE': {
                        'StatusCode': 'UINT16'
                    }
                }
            }

            /* 6. Delete this KeyHandle from internal storage */
            return vault.removeKeyID(keyID, KHAccessToken)
                .then(() => {
                    let STATUS = {
                        /* 7. Return UAF_CMD_STATUS_OK */
                        'TAG_STATUS_CODE': {
                            'StatusCode': new Uint16Array([CMD_STATUS_CODES_TO_INT['UAF_CMD_STATUS_OK']])
                        }
                    }

                    structure.TAG_UAFV1_DEREGISTER_CMD_RESPONSE = STATUS;

                    let TLVBUFFER = tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.DEREGISTER_CMD_RESPONSE_SCHEMA, structure);

                    return base64url.encode(TLVBUFFER);
                })
                .catch((ERROR) => {
                    console.error(`AUTHR DEREG ERROR: ${ERROR.message}`)

                    let STATUS = {
                        'TAG_STATUS_CODE': {
                            'StatusCode': new Uint16Array([CMD_STATUS_CODES_TO_INT[ERROR.message]])
                        }
                    }

                    structure.TAG_UAFV1_DEREGISTER_CMD_RESPONSE = STATUS;

                    let TLVBUFFER = tlv.generator.generateWithSchemaIgnoreMissing(window.UAF.TLVSchemas.DEREGISTER_CMD_RESPONSE_SCHEMA, structure);

                    return base64url.encode(TLVBUFFER);
                })
        }

        processRequest(requestTLV) {
            let requestBuffer = base64url.decode(requestTLV);
            let request = tlv.parser.parse(requestBuffer);
            let command = Object.keys(request)[0];
            switch(command) {
                case 'TAG_UAFV1_REGISTER_CMD':
                    return this.__Register(request[command]);
                break

                case 'TAG_UAFV1_SIGN_CMD':
                    return this.__Sign(request[command]);
                break

                case 'TAG_UAFV1_DEREGISTER_CMD':
                    return this.__Deregister(request[command]);
                break
            }

        }
    }

    window.UAF.UAFAuthenticator = UAFAuthenticator

})()
