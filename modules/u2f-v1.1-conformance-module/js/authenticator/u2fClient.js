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
    class U2FClient {
        constructor(origin) {
            this.origin         = breakURL(origin).origin;
            this.authenticator  = new window.CTAP.U2FAuthenticator();
            this.rpIDHashBuffer = window.navigator.fido.fido2.crypto.hash('sha256', breakURL(this.origin).host);
        }

        /**
         * Takes WebAuthn request, and returns base64url encoded clientData
         * @param  {Object} webauthnRequest - webauthnRequest
         * @param  {Object} modifiers       - modifiers for conformance testing
         * @return {String}                 - clientData
         */
        generateClientData(registerRequests, challenge, modifiers) {
            let origin = this.origin;

            let typ = undefined;
            if(registerRequests)
                typ = 'navigator.id.finishEnrollment';
            else
                typ = 'navigator.id.getAssertion';

            if(modifiers) {
                if(modifiers.clientDataJSONTypMissing)
                    typ = undefined;

                if(modifiers.clientDataJSONTypNull)
                    typ = null;

                if(modifiers.clientDataJSONTypInvalid)
                    typ = generateRandomTypeExcluding('string');

                if(modifiers.clientDataJSONTypEmpty)
                    typ = '';

                if(modifiers.clientDataJSONTypNotCreate)
                    typ = 'I swear I am webauthn.create!';

                if(modifiers.clientDataJSONTypNotGet)
                    typ = 'I am potatoe!';

                if(modifiers.clientDataJSONTypCreate)
                    typ = 'navigator.id.finishEnrollment';

                if(modifiers.clientDataJSONTypGet)
                    typ = 'navigator.id.getAssertion';


                if(modifiers.clientDataJSONChallengeMissing)
                    challenge = undefined

                if(modifiers.clientDataJSONChallengeNull)
                    challenge = null

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

                if(modifiers.clientDataJSONOriginNull)
                    origin = null

                if(modifiers.clientDataJSONOriginInvalid)
                    origin = generateRandomTypeExcluding('string');

                if(modifiers.clientDataJSONOriginEmpty)
                    origin = '';

                if(modifiers.clientDataJSONOriginNotMatching)
                    origin = 'https://evil.example.com/missme?';
            }
            
            let CollectedClientData = {origin, challenge, typ}

            return UTF8ToB64URL(JSON.stringify(CollectedClientData))
        }

        register(appId, registerRequests, registeredKeys, modifiers) {
            let registerRequest = registerRequests[0];

            let clientDataJSON  = this.generateClientData(registerRequest, registerRequest.challenge, modifiers);
            let clientDataHash  = window.navigator.fido.fido2.crypto.hash('sha256', base64url.decode(clientDataJSON));

            let authrResponse = this.authenticator.register(clientDataHash, this.rpIDHashBuffer, modifiers);

            return {
                'version': 'U2F_V2',
                'registrationData': base64url.encode(authrResponse),
                'clientData': clientDataJSON
            }
        }

        sign(appId, challenge, registeredKeys, modifiers) {
            let keyHandleBuffer = base64url.decode(registeredKeys[0].keyHandle);

            let clientDataJSON  = this.generateClientData(undefined, challenge, modifiers);
            let clientDataHash  = window.navigator.fido.fido2.crypto.hash('sha256', base64url.decode(clientDataJSON));

            let authrResponse = this.authenticator.sign(true, clientDataHash, this.rpIDHashBuffer, keyHandleBuffer, modifiers);

            return {
                'keyHandle': base64url.encode(keyHandleBuffer),
                'signatureData': base64url.encode(authrResponse),
                'clientData': clientDataJSON
            }
        }
    }


    window.CTAP.U2FClient = U2FClient;
})()
