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
    let validateAttestationFormat = (attestationFormat) => {
        let allowedFormats = ['packed', 'tpm', 'fido-u2f', 'android-key', 'none', 'android-safetynet'];

        if(allowedFormats.indexOf(attestationFormat) === -1)
            throw new Error('"' + attestationFormat + '" is not supported attestation format!');
    }

    let makeCredentialFields = ['rp', 'user', 'pubKeyCredParams', 'excludeCredentials', 'authenticatorSelection', 'attestation'];
    let getAssertionFields   = ['userVerification', 'allowCredentials', 'rpId'];
    let validateWebAuthnRequest = (webauthnRequest, expectedRequest) => {
        for(let key of Object.keys(webauthnRequest)) {
            if(expectedRequest === 'MakeCredential') {
                if(arrayContainsItem(getAssertionFields, key))
                    throw new Error('MakeCredential request contains GetAssertion fields! Only challenge, rp, user, pubKeyCredParams, excludeCredentials, authenticatorSelection, attestation and timeout are permitted!');
            } else {
                if(arrayContainsItem(makeCredentialFields, key))
                    throw new Error('GetAssertion request contains MakeCredential fields! Only challenge, allowCredentials, rpId, userVerification and timeout are permitted!');
            }
        }
    }

    class WebauthnClient {
        constructor(metadataStatement, attestationFormat, origin) {
            validateAttestationFormat(attestationFormat);

            this.attestationFormat = attestationFormat;
            this.origin            = breakURL(origin).origin;
            this.metadataStatement = metadataStatement;
            
            if(this.metadataStatement.protocolFamily === 'fido2') {
                this.authenticator = new window.CTAP.CTAP2Authenticator(this.metadataStatement, this.attestationFormat, this.origin)
            } else if(this.metadataStatement.protocolFamily === 'u2f') {
                this.authenticator = new window.CTAP.U2FAuthenticator(this.metadataStatement, this.attestationFormat, this.origin)
            } else {
                throw new Error(`"${this.metadataStatement.protocolFamily}" is an unknown protocolFamily!`);
            }
        }

        /**
         * Takes WebAuthn request, and returns base64url encoded clientData
         * @param  {Object} webauthnRequest - webauthnRequest
         * @param  {Object} modifiers       - modifiers for conformance testing
         * @return {String}                 - clientData
         */
        generateClientData(webauthnRequest, modifiers) {
            let origin    = this.origin;
            let challenge = webauthnRequest.challenge;

            let type = undefined;
            if(webauthnRequest.pubKeyCredParams)
                type = 'webauthn.create';
            else
                type = 'webauthn.get';

            let tokenBinding = undefined;

            if(modifiers) {
                if(modifiers.clientDataJSONTypeMissing)
                    type = undefined;

                if(modifiers.clientDataJSONTypeInvalid)
                    type = generateRandomTypeExcluding('string');

                if(modifiers.clientDataJSONTypeEmpty)
                    type = '';

                if(modifiers.clientDataJSONTypeNotCreate)
                    type = 'I swear I am webauthn.create!';

                if(modifiers.clientDataJSONTypeNotGet)
                    type = 'I am potatoe!';

                if(modifiers.clientDataJSONTypeCreate)
                    type = 'webauthn.create';

                if(modifiers.clientDataJSONTypeGet)
                    type = 'webauthn.get';

                if(modifiers.clientDataJSONChallengeMissing)
                    challenge = undefined

                if(modifiers.clientDataJSONChallengeInvalid)
                    challenge = generateRandomTypeExcluding('string');

                if(modifiers.clientDataJSONChallengeEmpty)
                    challenge = '';

                if(modifiers.clientDataJSONChallengeBadEncoding)
                    challenge = base64url.decode(challenge) + '==';

                if(modifiers.clientDataJSONChallengeNotMatching)
                    challenge = generateRandomString();


                if(modifiers.clientDataJSONOriginMissing)
                    origin = undefined

                if(modifiers.clientDataJSONOriginInvalid)
                    origin = generateRandomTypeExcluding('string');

                if(modifiers.clientDataJSONOriginEmpty)
                    origin = '';

                if(modifiers.clientDataJSONOriginNotMatching)
                    origin = 'https://evil.example.com/missme?';


                if(modifiers.clientDataJSONTokenBindingInvalid)
                    tokenBinding = generateRandomTypeExcluding('object');

                if(modifiers.clientDataJSONTokenBindingStatusFieldMissing)
                    tokenBinding = {}

                if(modifiers.clientDataJSONTokenBindingStatusFieldIncorrect)
                    tokenBinding = { 'status': 'bananas' };
            }
            
            let CollectedClientData = {origin, challenge, type, tokenBinding}

            return UTF8ToB64URL(JSON.stringify(CollectedClientData))
        }

        createCredential(webauthnRequest, modifiers) {
            try {
                validateWebAuthnRequest(webauthnRequest, 'MakeCredential');
                let clientDataJSON = this.generateClientData(webauthnRequest, modifiers);
                let clientDataHash = window.navigator.fido.fido2.crypto.hash('sha256', base64url.decode(clientDataJSON)); 

                webauthnRequest.clientDataHash = clientDataHash;
                return this.authenticator.makeCredential(webauthnRequest, modifiers)
                    .then((response) => {
                        return {
                            'id': base64url.encode(response.credId),
                            'rawId': base64url.encode(response.credId),
                            'response': {
                                'attestationObject': base64url.encode(response.attestationObject),
                                'clientDataJSON': clientDataJSON
                            },
                            'type': 'public-key'
                        }
                    })
            } catch(e) {
                return Promise.reject('Error while creating credential: ' + e)
            }
        }

        requestAssertion(webauthnRequest, modifiers) {
            try {
                validateWebAuthnRequest(webauthnRequest, 'GetAssertion');
                let clientDataJSON = this.generateClientData(webauthnRequest, modifiers);
                let clientDataHash = window.navigator.fido.fido2.crypto.hash('sha256', base64url.decode(clientDataJSON));

                let promises = [];
                if(!webauthnRequest.allowCredentials || webauthnRequest.allowCredentials.length === 0) {
                        webauthnRequest.clientDataHash = clientDataHash;
                        let p = this.authenticator.getAssertion(webauthnRequest, modifiers)
                        promises.push(p);
                } else {
                    for(let cred of webauthnRequest.allowCredentials) {
                        webauthnRequest.clientDataHash = clientDataHash;
                        webauthnRequest.credId         = base64url.decode(cred.id);

                        let p = this.authenticator.getAssertion(webauthnRequest, modifiers)
                        promises.push(p);
                    }
                }

                return Promise.race(promises)
                    .then((response) => {
                        return {
                            'id': base64url.encode(response.credId),
                            'rawId': base64url.encode(response.credId),
                            'response': {
                                'authenticatorData': base64url.encode(response.authenticatorData),
                                'signature': base64url.encode(response.signature),
                                'userHandle': base64url.encode(response.userHandle),
                                'clientDataJSON': clientDataJSON
                            },
                            'type': 'public-key'
                        }
                    })
            } catch(e) {
                console.log('Error while getting assertion: ' + e)
                return Promise.reject('Error while getting assertion: ' + e)
            }
        }
    }


    window.CTAP.WebauthnClient = WebauthnClient;
})()
