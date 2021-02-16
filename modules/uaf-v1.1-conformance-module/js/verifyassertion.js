(function() {    
    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    })

    let DERTLV = new TLV({
        'TagFieldSize' : 1,
        'LengthFieldSize' : 1,
        'TagDirectory': TAG_ASN1_DER
    })


    /**
     * Takes 32 bytes long R and S buffers and returns DER OCTET INTEGER SEQUECE SIGNATURE
     * @param  {ArrayBuffer} R
     * @param  {ArrayBuffer} S
     * @return {ArrayBuffer}   - DER OCTET INTEGER SEQUECE SIGNATURE
     */
    let RandSbuffersToDERSignature = (R, S) => {
        if (R.byteLength !== 32 || S.byteLength !== 32)
            throw new Error(`R and S coefficients MUST be 32 bytes long!`);

        if (new Uint8Array(R)[0] > 0x7F)
            R = mergeArrayBuffers(new Uint8Array([0x00]), R);

        if (new Uint8Array(S)[0] > 0x7F)
            S = mergeArrayBuffers(new Uint8Array([0x00]), S);

        let Rcoef = mergeArrayBuffers(new Uint8Array([0x02, R.byteLength]), R)
        let Scoef = mergeArrayBuffers(new Uint8Array([0x02, S.byteLength]), S)
        return mergeArrayBuffers(new Uint8Array([0x30, Rcoef.byteLength + Scoef.byteLength]), Rcoef, Scoef)
    }

    /**
     * Converts given valid FIDO ECDSA RAW or DER signature into OCTET DER 
     * @param  {String} signatureAlgorithm   - TAG_ALG Algorithm Identifier
     * @param  {ArrayBuffer} signatureBuffer - Signature buffer
     * @return {ArrayBuffer}                 - OCTET DER Signature
     */
    let FIDOECDSASignatureToDER = (signatureAlgorithm, signatureBuffer) => {
        let R;
        let S;

        if (signatureAlgorithm === 'ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW' ||
           signatureAlgorithm === 'ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW') {

            if (signatureBuffer.byteLength !== 64)
                throw new Error('RAW ECDSA signature MUST be 64 bytes long!');

            R = signatureBuffer.slice(0, 32);
            S = signatureBuffer.slice(32, 64);

            return RandSbuffersToDERSignature(R, S)

        } else if (signatureAlgorithm === 'ALG_SIGN_SECP256R1_ECDSA_SHA256_DER' ||
                   signatureAlgorithm === 'ALG_SIGN_SECP256K1_ECDSA_SHA256_DER') {

            if (signatureBuffer.byteLength > 72)
                throw new Error('DER ECDSA signature MUST be less than 72 bytes long!');

            return signatureBuffer
        } else
            throw new Error(`Uknown signature algorithm "${signatureAlgorithm}"!`);
    }

    /**
     * Converts given valid FIDO RSAPSS RAW or DER signature into RAW 256byte buffer
     * @param  {String} signatureAlgorithm   - TAG_ALG Algorithm Identifier
     * @param  {ArrayBuffer} signatureBuffer - Signature buffer
     * @return {ArrayBuffer}                 - RAW 256byte buffer
     */
    let FIDORSAPSSSignatureToRAW = (signatureAlgorithm, signatureBuffer) => {
        if (signatureAlgorithm === 'ALG_SIGN_RSASSA_PSS_SHA256_RAW') {
            if (signatureBuffer.byteLength !== 256)
                throw new Error('RAW RSAPSS signature MUST be 256 bytes long!');
            return signatureBuffer
        } else if (signatureAlgorithm === 'ALG_SIGN_RSASSA_PSS_SHA256_DER') {
            if (signatureBuffer.byteLength !== 260)
                throw new Error('DER RSAPSS signature MUST be 260 bytes long!');

            return signatureBuffer.slice(4)
        } else
            throw new Error(`Uknown signature algorithm "${signatureAlgorithm}"!`);
    }

    /**
     * Takes signature algorithm and ECDSA keyBuffer and returns JSRSASign keyObject
     * @param  {String}      signatureAlgorithm - Signature algorithm identifier
     * @param  {ArrayBuffer} keyBuffer          - Public key buffer
     * @return {KeyObject}
     */
    let FIDOECDSAPublicKeyToKeyObject = (signatureAlgorithm, keyBuffer) => {
        let pubKeyUint8 = new Uint8Array(keyBuffer);
        let pubKeyHEX;
        let pubKey;

        if (signatureAlgorithm.indexOf('_SECP256R1_') !== -1) {
            pubKey = new jsrsasign.KJUR.crypto.ECDSA({
                curve: 'secp256r1'
            })
        } else if (signatureAlgorithm.indexOf('_SECP256K1_') !== -1) {
            pubKey = new jsrsasign.KJUR.crypto.ECDSA({
                curve: 'secp256k1'
            })
        } else 
            throw new Error(`Uknown signature algorithm ${signatureAlgorithm}`);

        /* If RAW encoded */
        if (pubKeyUint8[0] === 0x04)
            pubKeyHEX = hex.encode(keyBuffer);

        /* If DER encoded */
        else {
            let PUBKEYSTRUCT = DERTLV.parser.parse(keyBuffer);
            pubKeyHEX = PUBKEYSTRUCT['SEQUENCE']['BITSTRING'].substr(2);
        }

        pubKey.setPublicKeyHex(pubKeyHEX);

        return pubKey;
    }

    /**
     * Takes RSAPSS public key buffer, and returns JSRSASign KeyObject
     * @param  {ArrayBuffer} keyBuffer - KeyBuffer
     * @return {KeyObject}             - JSRSASign RSA KeyObject
     */
    let FIDORSAPSSPublicKeyToKeyObject = (keyBuffer) => {
        if (keyBuffer.byteLength < 257)
            throw new Error('Invalid public key! MUST be min of 257 bytes for RAW, and 268 for DER')

        let pubKeyUint8 = new Uint8Array(keyBuffer);
        let n;
        let e;

        /* DER Signature 4 SEQ + 4 INT + 1 PADDING + 256 n + 2 INT = 267 bytes */
        if (pubKeyUint8[0] === 0x30 && pubKeyUint8.byteLength > 267) {
            n = keyBuffer.slice(9, 265)
            e = keyBuffer.slice(265 + 2)
        } else {
            n = keyBuffer.slice(0, 256)
            e = keyBuffer.slice(256)
        }

        return jsrsasign.KEYUTIL.getKey({
            'alg': 'PS256',
            'e': base64url.encode(e),
            'ext': true,
            'key_ops': [
                'verify'
            ],
            'kty': 'RSA',
            'n': base64url.encode(n)
        })
    }

    /**
     * Takes UAFV1TLV and returns JSON struct
     * @param  {String} assertion - base64url UAFV1TLV assertion
     * @return {Object}           - JSON struct
     */
    let getAssertionStruct = (assertion) => {
        let buffer = base64url.decode(assertion);
        return tlv.parser.parse(buffer);
    }

    /**
     * Takes UAFV1TLV and returns TAG_UAFV1_KRD buffer
     * @param  {String}      assertion - base64url UAFV1TLV assertion
     * @return {ArrayBuffer}           - TAG_UAFV1_KRD buffer
     */
    let getKRDBuffer = (assertion) => {
        let buffer = base64url.decode(assertion);
        let structRAW = tlv.parser.parseButSkipValueDecoding(buffer);

        if (!structRAW['TAG_UAFV1_REG_ASSERTION'])
            throw new Error('Assertion missing TAG_UAFV1_REG_ASSERTION!');

        return tlv.parser.searchTAG(buffer, 'TAG_UAFV1_KRD')
    }

    /**
     * Takes UAFV1TLV and returns TAG_UAFV1_SIGNED_DATA buffer
     * @param  {String}      assertion - base64url UAFV1TLV assertion
     * @return {ArrayBuffer}           - TAG_UAFV1_SIGNED_DATA buffer
     */
    let getSIGNEDDATABuffer = (assertion) => {
        let buffer = base64url.decode(assertion);
        let structRAW = tlv.parser.parseButSkipValueDecoding(buffer);

        if (!structRAW['TAG_UAFV1_AUTH_ASSERTION'])
            throw new Error('Assertion missing TAG_UAFV1_AUTH_ASSERTION!');

        return tlv.parser.searchTAG(buffer, 'TAG_UAFV1_SIGNED_DATA')
    }

    /**
     * Takes signature algorithm, signature buffer, data buffer, and JSRSASign key object, and returns if signature is valid
     * @param  {String} signatureAlgorithm   - TAG_ALG algorithm identifier
     * @param  {ArrayBuffer} signatureBuffer - ECDSA DER
     * @param  {ArrayBuffer} dataBuffer      - data buffer
     * @param  {KeyObject}   keyObject       - JSRSASing key object
     * @return {Boolean}                     - is signature valid
     */
    let verifyECDSASignature = (signatureBuffer, dataBuffer, keyObject) => {
        let dataHEX      = hex.encode(dataBuffer);
        let signatureHEX = hex.encode(signatureBuffer);

        let sig = new jsrsasign.crypto.Signature({alg: 'SHA256withECDSA'});
        sig.init(keyObject);
        sig.updateHex(dataHEX)

        return sig.verify(signatureHEX)
    }

    /**
     * Takes signature buffer, data buffer, and JSRSASign key object, and returns if signature is valid
     * @param  {String} signatureAlgorithm   - TAG_ALG algorithm identifier
     * @param  {ArrayBuffer} signatureBuffer - RSA PSS RAW 256 byte buffer
     * @param  {ArrayBuffer} dataBuffer      - data buffer
     * @param  {KeyObject}   keyObject       - JSRSASing key object
     * @return {Promise}
     */
    let verifyRSAPSSSignature = (signatureBuffer, dataBuffer, pubKeyObject) => {
        let jwKey = jsrsasign.KEYUTIL.getJWKFromKey(pubKeyObject);

        return window.crypto.subtle.importKey(
            'jwk',
            jwKey,
            {
                'name': 'RSA-PSS',
                'hash': {
                    'name': 'SHA-256'
                }
            },
            false,
            ['verify']
        )
        .then((key) => {
            return window.crypto.subtle.verify(
                {
                    'name': 'RSA-PSS',
                    'saltLength': 32
                },
                key,
                signatureBuffer,
                dataBuffer
            )
        })
    }

    /**
     * Takes UAFV1TLV registration assertion, returns public keys
     * @param  {String} assertion - base64url encoded assertion
     * @return {Object}           - {'publicKey': {}, 'certificatePublicKey': {}}
     */
    let extractPublicKeysFromAssertion = (assertion) => {
        let STRUCT = getAssertionStruct(assertion);
        let keysObject = {}

        if (STRUCT['TAG_UAFV1_REG_ASSERTION']) {
            let signatureAlgorithm = STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.SignatureAlgAndEncoding;
            let keyBuffer = base64url.decode(STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_PUB_KEY)

            if (signatureAlgorithm.indexOf('ECDSA') !== -1)
                keysObject['publicKey'] = FIDOECDSAPublicKeyToKeyObject(signatureAlgorithm, keyBuffer);
            else
                keysObject['publicKey'] = FIDORSAPSSPublicKeyToKeyObject(keyBuffer);

            if (STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL) {
                let certB64URL = STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_ATTESTATION_CERT;
               
                if(type(certB64URL) === 'Array')
                    certB64URL = certB64URL[0];

                let certPem = base64urlCertToPem(certB64URL);
                keysObject['certificatePublicKey'] = jsrsasign.KEYUTIL.getKey(certPem);
            }
            
            return keysObject
        } else 
            throw new Error(`Given assertion is not TAG_UAFV1_REG_ASSERTION!`)
    }

    /**
     * Takes UAFV1TLV assertion, and verifies it's signature
     * @param  {String} assertion    - base64url encoded assertion
     * @param  {KeyObject} keyObject - JSRSASign public key object
     * @return {Boolean}             - is signature valid
     */
    let verifyAssertion = (assertion, keyObject) => {
        return Promise.resolve({})
            .then(() => {
                let STRUCT = getAssertionStruct(assertion);
                let dataBuffer;
                let key;
                let DERSignatureBuffer;

                if (STRUCT['TAG_UAFV1_REG_ASSERTION']) {
                    let signatureAlgorithm = STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_UAFV1_KRD.TAG_ASSERTION_INFO.SignatureAlgAndEncoding;

                    dataBuffer = getKRDBuffer(assertion);
                    keysObject = extractPublicKeysFromAssertion(assertion);

                    if (signatureAlgorithm.indexOf('ECDSA') !== -1) {
                        if (STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL) {
                            let signatureBuffer = base64url.decode(STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_SIGNATURE);
                            DERSignatureBuffer = FIDOECDSASignatureToDER(signatureAlgorithm, signatureBuffer);
                            key = keysObject['certificatePublicKey'];
                        } else {
                            let signatureBuffer = base64url.decode(STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE.TAG_SIGNATURE);
                            DERSignatureBuffer = FIDOECDSASignatureToDER(signatureAlgorithm, signatureBuffer);

                            key = keysObject['publicKey'];
                        }

                        return verifyECDSASignature(DERSignatureBuffer, dataBuffer, key);
                    } else {
                        if (STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL) {
                            let signatureBuffer = base64url.decode(STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_FULL.TAG_SIGNATURE);
                            DERSignatureBuffer = FIDORSAPSSSignatureToRAW(signatureAlgorithm, signatureBuffer);

                            key = keysObject['certificatePublicKey'];
                        } else {
                            let signatureBuffer = base64url.decode(STRUCT.TAG_UAFV1_REG_ASSERTION.TAG_ATTESTATION_BASIC_SURROGATE.TAG_SIGNATURE);
                            DERSignatureBuffer = FIDORSAPSSSignatureToRAW(signatureAlgorithm, signatureBuffer);

                            key = keysObject['publicKey'];
                        }

                        return verifyRSAPSSSignature(DERSignatureBuffer, dataBuffer, key);
                    }
                } else if (STRUCT['TAG_UAFV1_AUTH_ASSERTION']) {
                    if (!keyObject)
                        throw new Error('keyObject required to verify TAG_UAFV1_AUTH_ASSERTION');

                    let signatureAlgorithm = STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_UAFV1_SIGNED_DATA.TAG_ASSERTION_INFO.SignatureAlgAndEncoding

                    dataBuffer = getSIGNEDDATABuffer(assertion);
                    let signatureBuffer = base64url.decode(STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);

                    if (signatureAlgorithm.indexOf('ECDSA') !== -1) {
                        DERSignatureBuffer = FIDOECDSASignatureToDER(signatureAlgorithm, signatureBuffer);
                        return verifyECDSASignature(DERSignatureBuffer, dataBuffer, keyObject);
                    } else {
                        DERSignatureBuffer = FIDORSAPSSSignatureToRAW(signatureAlgorithm, signatureBuffer);
                        return verifyRSAPSSSignature(DERSignatureBuffer, dataBuffer, keyObject)
                    }

                }
            })
    }

    window.verifyAssertion = verifyAssertion;
    window.extractPublicKeysFromAssertion = extractPublicKeysFromAssertion;
    window.getAssertionStruct = getAssertionStruct;
})()