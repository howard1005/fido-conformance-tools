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
    let batchKey = {
        'cert': 'MIIEKzCCAhOgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDMxNjE0MzUyN1oXDTI4MDMxMzE0MzUyN1owgawxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETzpeXqtsH7yul/bfZEmWdix773IAQCp2xvIw9lVvF6qZm1l/xL9Qiq+OnvDNAT9aub0nkUvwgEN4y8yxG4m1RqMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUVk33wPjGVbahH2xNGfO/QeL9AXkwDQYJKoZIhvcNAQEFBQADggIBAI+/jI31FB+8J2XxzBXMuI4Yg+vAtq07ABHJqnQpUmt8lpOzmvJ0COKcwtq/7bpsgSVBJ26zhnyWcm1q8V0ZbxUvN2kH8N7nteIGn+CJOJkHDII+IbiH4+TUQCJjuCB52duUWL0fGVw2R13J6V+K7U5r0OWBzmtmwwiRVTggVbjDpbx2oqGAwzupG3RmBFDX1M92s3tgywnLr+e6NZal5yZdS8VblJGjswDZbdY+Qobo2DCN6vxvn5TVkukAHiArjpBBpAmuQfKa52vqSCYRpTCm57fQUZ1c1n29OsvDw1x9ckyH8j/9Xgk0AG+MlQ9Rdg3hCb7LkSPvC/zYDeS2Cj/yFw6OWahnnIRwO6t4UtLuRAkLrjP1T7nk0zu1whwj7YEwtva45niWWh6rdyg/SZlfsph3o/MZN5DwKaSrUaEO6b+numELH5GWjjiPgfgPKkIof+D40xaKUFBpNJzorQkAZCJWuHvXRpBZWFVh/UhNlGhX0mhz2yFlBrujYa9BgvIkdJ8Keok6qfAn+r5EEFXcSI8vGY7OEF01QKXVpu8+FW0uSxtQ991AcFD6KjvR51l7e61visUgduhZRIq9bYzeCIxnK5Jhm3o/NJE2bOp2NmVwVe4kjuJX87wo3Ba41bXgwIpdiLWyWJhSHPmJI/1ibRTZ5XO92xbPPSnnkXrF',
        'privateKey': '28857aaed6dd6efc6e64762f53f7c3da3fa34e45b55bb040612d4f611f49f834',
        'publicKey': '044f3a5e5eab6c1fbcae97f6df644996762c7bef7200402a76c6f230f6556f17aa999b597fc4bf508aaf8e9ef0cd013f5ab9bd27914bf0804378cbccb11b89b546'
    }

    class U2FAuthenticator {
        constructor(metadataStatement, attestationFormat, origin) {
            this.keyDB   = {};
            this.counter = 1;

            this.metadataStatement = metadataStatement;
            this.attestationFormat = attestationFormat;
            this.origin = origin;
            this.rpIDHashBuffer    = window.navigator.fido.fido2.crypto.hash('sha256', breakURL(this.origin).host);

        }

        /**
         * Takes required params and returns register structure containing: reserverByte, PublicKeyBuffer, keyHandleLength, keyHandleBuffer, attestationCertBuff, signatureBuffer
         * @param  {Uint8Array} challengeBuffer
         * @param  {Uint8Array} appParamBuffer
         * @return {Object}                     - {reserverByte, PublicKeyBuffer, keyHandleLength, keyHandleBuffer, attestationCertBuff, signatureBuffer}            
         */
        getRegisterStruct(challengeBuffer, appParamBuffer) {
            if(challengeBuffer.byteLength !== 32 || appParamBuffer.byteLength !== 32)
                throw new Error('Challenge or/and parameter buffers are not 32 bytes long!');

            this.counter += 1;

            let keyHandleBuffer     = this.generateNewKeyPair();
            let RFU                 = new Uint8Array([0x00]);
            let PublicKeyBuffer     = this.getPublicKeyBuffer(keyHandleBuffer);
            let keyHandleLength     = new Uint8Array([keyHandleBuffer.byteLength])

            let signatureBaseBuffer = mergeArrayBuffers(RFU, appParamBuffer, challengeBuffer, keyHandleBuffer, PublicKeyBuffer);

            let signatureBuffer     = this.signWithBatchPrivateKey(signatureBaseBuffer)
            let reserverByte        = new Uint8Array([0x05]);
            let attestationCertBuff = this.getBatchCertificateBuffer();

            return {reserverByte, PublicKeyBuffer, keyHandleLength, keyHandleBuffer, attestationCertBuff, signatureBuffer}
        }

        /**
         * Takes required params and returns raw U2F register response
         * @param  {Uint8Array} challengeBuffer
         * @param  {Uint8Array} appParamBuffer
         * @return {Uint8Array}
         */
        register(challengeBuffer, appParamBuffer) {
            let registerStruct = getRegisterStruct(challengeBuffer, appParamBuffer);

            return mergeArrayBuffers(registerStruct.reserverByte, registerStruct.PublicKeyBuffer, registerStruct.keyHandleLength, registerStruct.keyHandleBuffer, registerStruct.attestationCertBuff, registerStruct.signatureBuffer)
        }

        /**
         * Generates AuthData buffer
         * @param  {Uint8Array} rpIDHashBuffer
         * @param  {Object}    flagsStruct
         * @param  {Uint8Array} counterBuffer
         * @param  {Uint8Array} aaguidBuffer
         * @param  {Uint8Array} credId
         * @param  {Uint8Array} cosePublicKey
         * @return {Uint8Array}
         */
        generateAuthData(rpIDHashBuffer, flagsStruct, counterBuffer, aaguidBuffer, credId, cosePublicKey) {
            if(!rpIDHashBuffer || !flagsStruct || !counterBuffer)
                throw new Error('Missing rpIDHashBuffer or/and flagsStruct or/and counterBuffer argument!');

            let flags = 0;

            let upFlag = 0x01; // Test of User Presence
            let uvFlag = 0x04; // User Verification
            let atFlag = 0x40; // Attested credential data included (AT).
            let edFlag = 0x80; // Extension data

            if(flagsStruct.up)
                flags += upFlag;

            let credIdLength = new Uint16Array();
            if(aaguidBuffer || credId || cosePublicKey) {
                if(!aaguidBuffer || !credId || !cosePublicKey)
                    throw new Error('Missing aaguidBuffer or/and credId or/and cosePublicKey argument!');

                flags += atFlag;
                credIdLength = new Uint16Array([credId.byteLength])
            }

            aaguidBuffer  = aaguidBuffer  || new Uint8Array();
            credId        = credId        || new Uint8Array();
            cosePublicKey = cosePublicKey || new Uint8Array();

            let flagsBuffer = new Uint8Array([flags]);

            counterBuffer = counterBuffer;
            credIdLength  = getBigEndianEcoding(credIdLength);

            return mergeArrayBuffers(rpIDHashBuffer, flagsBuffer, counterBuffer, aaguidBuffer, credIdLength, credId, cosePublicKey)
        }

        makeCredential(makeCredentialRequestStruct, modifiers) {
            try {
                let clientDataHash   = makeCredentialRequestStruct.clientDataHash;
                let registerStruct   = this.getRegisterStruct(clientDataHash, this.rpIDHashBuffer);

                let flagsStruct      = {'up': true};
                let counterBuffer    = getBigEndianEcoding(new Uint32Array([this.counter]));
                let aaguidBuffer     = hex.decode('00000000000000000000000000000000');
                let keyHandleBuffer  = registerStruct.keyHandleBuffer;
                let cosePubKeyBuffer = PKCSECDSAtoCOSE(registerStruct.PublicKeyBuffer);

                if(modifiers) {
                    if(modifiers.aaguidNot00)
                        aaguidBuffer = hex.decode('937dd8ca647e4ed3972943a796cf572a');
                }
                let authData         = this.generateAuthData(this.rpIDHashBuffer, flagsStruct, counterBuffer, aaguidBuffer, keyHandleBuffer, cosePubKeyBuffer)
                let fmt              = 'fido-u2f';
                let attStmt          = {
                    'sig': registerStruct.signatureBuffer,
                    'x5c': [registerStruct.attestationCertBuff]
                }

                if(modifiers) {
                    if(modifiers.sigUnverifiable)
                        attStmt.sig = mergeArrayBuffers(attStmt.sig.slice(8), generateRandomBuffer(8));
                }

                let makeCredentialRespStruct = {authData, fmt, attStmt}
                let attestationObject        = window.navigator.fido.fido2.cbor.JSONToCBORArrayBuffer(makeCredentialRespStruct);
                let credId                   = registerStruct.keyHandleBuffer;
                return Promise.resolve({
                    credId,
                    attestationObject
                })
            } catch(e) {
                return Promise.reject('Error while creating credential: ' + e)
            }
        }

        /**
         * Takes required params and returns sign structure containing: UP, counterBuffer, signatureBuffer
         * @param  {Boolean} enforceUserPresense
         * @param  {Uint8Array} challengeBuffer
         * @param  {Uint8Array} appParamBuffer
         * @param  {Uint8Array} keyHandleBuffer
         * @return {Object}                      - {UP, counterBuffer, signatureBuffer}
         */
        getSignStruct(enforceUserPresense, challengeBuffer, appParamBuffer, keyHandleBuffer) {
            if(!this.keyHandleExists(keyHandleBuffer))
                throw new Error('Unknown keyHandle!');

            let UP = new Uint8Array([0x00]);

            if(enforceUserPresense)
                UP = new Uint8Array([0x01]);

            this.counter += 1;
            let counterBuffer = new Uint32Array([this.counter]);

            let signatureBaseBuffer = mergeArrayBuffers(appParamBuffer, UP, counterBuffer, challengeBuffer);
            let signatureBuffer     = this.signWithKeyHandlePrivateKey(keyHandleBuffer, signatureBaseBuffer);

            return {UP, counterBuffer, signatureBuffer}
        }

        /**
         * Takes required params and returns U2F raw response
         * @param  {Boolean} enforceUserPresense
         * @param  {Uint8Array} challengeBuffer
         * @param  {Uint8Array} appParamBuffer
         * @param  {Uint8Array} keyHandleBuffer
         * @return {Uint8Array}                  - RAW U2F response
         */
        sign(enforceUserPresense, challengeBuffer, appParamBuffer, keyHandleBuffer) {
            let signStruct = this.getSignStruct(enforceUserPresense, challengeBuffer, appParamBuffer, keyHandleBuffer)
            return mergeArrayBuffers(signStruct.UP, signStruct.counterBuffer, signStruct.signatureBuffer)
        }


        getAssertion(getAssertionRequestStruct) {
            try {
                let signStruct = this.getSignStruct(true, getAssertionRequestStruct.clientDataHash, this.rpIDHashBuffer, getAssertionRequestStruct.credId);

                let authenticatorData = this.generateAuthData(this.rpIDHashBuffer, {'up': true}, signStruct.counterBuffer);
                let signature         = signStruct.signatureBuffer;
                let credId            = getAssertionRequestStruct.credId;
                let userHandle        = new Uint8Array();

                return Promise.resolve({
                    authenticatorData, signature, credId, userHandle
                })
            } catch(e) {
                return Promise.reject('Error while creating credential: ' + e)
            }
        }

    /* ---------- KEYHANDLE ----------- */
        signWithKeyHandlePrivateKey(keyHandleBuffer, data) {
            if(!this.keyHandleExists(keyHandleBuffer))
                throw new Error('Unknown keyHandle!');

            let keyHandleString = base64url.encode(keyHandleBuffer);
            let privateKey = this.keyDB[keyHandleString].private;

            let dataHash = window.navigator.fido.fido2.crypto.hash('sha256', data);
            return window.navigator.fido.fido2.crypto.signWithECDSAKeyDER('p256', privateKey, dataHash)
        }

        getPublicKeyBuffer(keyHandleBuffer) {
            if(!this.keyHandleExists(keyHandleBuffer))
                throw new Error('Unknown keyHandle!');

            let keyHandleString = base64url.encode(keyHandleBuffer);
            return hex.decode(this.keyDB[keyHandleString].public);
        }

        /**
         * Returns generates keyPair, and returns corresponding keyHandle
         * @return {[type]} [description]
         */
        generateNewKeyPair() {
            let keyHandleBuffer = generateRandomBuffer(32);
            let keyHandleString = base64url.encode(keyHandleBuffer);
            let newKeypair = window.navigator.fido.fido2.crypto.generateECDSAKeypair('p256');

            this.keyDB[keyHandleString] = newKeypair;
            return keyHandleBuffer
        }

        keyHandleExists(keyHandleBuffer) {
            let keyHandleString = base64url.encode(keyHandleBuffer);

            return !!this.keyDB[keyHandleString]
        }

    /* ---------- BATCH ATTESTATION ---------- */
        getBatchCertificateBuffer() {
            return base64.decode(batchKey.cert)
        }

        signWithBatchPrivateKey(data) {
            let dataHash = window.navigator.fido.fido2.crypto.hash('sha256', data);
            return window.navigator.fido.fido2.crypto.signWithECDSAKeyDER('p256', batchKey.privateKey, dataHash)
        }
    }

    window.CTAP.U2FAuthenticator = U2FAuthenticator;
})()
