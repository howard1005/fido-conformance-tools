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

const crypto   = require('crypto');
const elliptic = require('elliptic');
const nodersa  = require('node-rsa');
const cbor     = require('./cbordep');

/**
 * Decode initial bytes of buffer as ASN and return the length of the encoded structure.
 * See http://en.wikipedia.org/wiki/X.690
 * Only SEQUENCE top-level identifier is supported (which covers all certs luckily)
 * Stolen from https://github.com/ashtuchkin/u2f/blob/master/index.js#L62
 * @param  {ArrayBuffer} buf - ASN1 buffer
 * @return {Number}          - The length of the found ASN1 structure
 */
let asnLen = (buf) => {
    if (buf.length < 2 || buf[0] != 0x30)
        throw new Error("Invalid data: Not a SEQUENCE ASN/DER structure");

    var len = buf[1];
    if (len & 0x80) { // long form
        var bytesCnt = len & 0x7F;
        if (buf.length < 2+bytesCnt)
            throw new Error("Invalid data: ASN structure not fully represented");
        len = 0;
        for (var i = 0; i < bytesCnt; i++)
            len = len*0x100 + buf[2+i];
        len += bytesCnt; // add bytes for length itself.
    }

    return len + 2; // add 2 initial bytes: type and length.
}


let hash = (hashFunction, data) => {
    if(!hashFunction)
        throw new Error('hashFunction argument is missing!');

    hashFunction = hashFunction.replace('-', '');

    if(!data)
        throw new Error('data argument is missing!');

    let hash = crypto.createHash(hashFunction);
    hash.update(data);

    return new Uint8Array(hash.digest())
}

let COSE_KEYS = {
    'kty' : 1,
    'alg' : 3,
    'crv' : -1,
    'x'   : -2,
    'y'   : -3,
    'n'   : -1,
    'e'   : -2
}

let COSE_KTY = {
    'OKP': 1, // https://tools.ietf.org/html/rfc8152#section-13
    'EC2': 2, // https://tools.ietf.org/html/rfc8152#section-13
    'RSA': 3  // https://tools.ietf.org/html/rfc8230#section-4
}

let ALG_TO_SCHEME = {
    '-37'   : 'pss-sha256',
    '-38'   : 'pss-sha384',
    '-39'   : 'pss-sha512',
    '-257'  : 'pkcs1-sha256',
    '-258'  : 'pkcs1-sha384',
    '-259'  : 'pkcs1-sha512',
    '-65535': 'pkcs1-sha1'
}

let COSE_ALG_HASH = {
    '-257'  : 'SHA-256', // RSASSA-PKCS1-v1_5 w/ SHA-256 Section 8.2 of [RFC8017]
    '-258'  : 'SHA-384', // RSASSA-PKCS1-v1_5 w/ SHA-384 Section 8.2 of [RFC8017]
    '-259'  : 'SHA-512', // RSASSA-PKCS1-v1_5 w/ SHA-512 Section 8.2 of [RFC8017]
    '-65535': 'SHA-1',   // RSASSA-PKCS1-v1_5 w/ SHA-1 Section 8.2 of [RFC8017]
    '-39'   : 'SHA-512',  // RSASSA-PSS w/ SHA-512  [RFC8230]
    '-38'   : 'SHA-384',  // RSASSA-PSS w/ SHA-384 [RFC8230]
    '-37'   : 'SHA-256',   // RSASSA-PSS w/ SHA-256 [RFC8230]
    '-260'  : 'SHA-256', // TPM_ECC_BN_P256 curve w/ SHA-256
    '-261'  : 'SHA-512', // ECC_BN_ISOP512 curve w/ SHA-512
    '-7'    : 'SHA-256',   // ECDSA w/ SHA-256 
    '-36'   : 'SHA-384',  // ECDSA w/ SHA-384 
    '-37'   : 'SHA-512'  // ECDSA w/ SHA-512
}

let COSE_CRV_CURVE = {
    1: 'p256',
    8: 'secp256k1',
    2: 'p384',
    3: 'p521',
    6: 'curve25519'
}

module.exports =  {
    /**
     * Takes a hash-function name, and data buffer and returns a hash of it
     * @param  {String} hashFunction - hash function name
     * @param  {Buffer} data         - data buffer
     * @return {Buffer}              - hash buffer
     */
    'hash': hash,

    /**
     * Takes COSE key buffer, message and signature buffers and verifies them
     * @param  {Buffer} cosekey
     * @param  {Buffer} messageBuffer
     * @param  {Buffer} signatureBuffer
     * @return {Boolean}
     */
    'verifySignatureCOSE': (cosekey, messageBuffer, signatureBuffer) => {
        let coseKey = cbor.CBORBufferToNATIVESTRUCT(cosekey)[0];
        let hashAlg = COSE_ALG_HASH[coseKey.get(COSE_KEYS.alg)];

        let result = false;
        if(coseKey.get(COSE_KEYS.kty) === COSE_KTY.RSA) {
            let signingScheme = ALG_TO_SCHEME[coseKey.get(COSE_KEYS.alg)];

            let key = new nodersa(undefined, { signingScheme });
            key.importKey({
                n: coseKey.get(COSE_KEYS.n),
                e: 65537
            }, 'components-public');

            result = key.verify(messageBuffer, signatureBuffer)
        } else if(coseKey.get(COSE_KEYS.kty) === COSE_KTY.EC2) {
            let xCoefficient = coseKey.get(COSE_KEYS.x);
            let yCoefficient = coseKey.get(COSE_KEYS.y);
            
            let keyBuffer   = Buffer.concat([Buffer.from([0x04]), xCoefficient, yCoefficient]);
            let messageHash = hash(hashAlg, messageBuffer);
            let curve       = COSE_CRV_CURVE[coseKey.get(COSE_KEYS.crv)];

            let ec  = new elliptic.ec(curve);
            let key = ec.keyFromPublic(keyBuffer);

            result = key.verify(messageHash, signatureBuffer);
        } else if(coseKey.get(COSE_KEYS.kty) === COSE_KTY.OKP) {
            let keyBuffer   = coseKey.get(COSE_KEYS.x)

            let key = new elliptic.eddsa('ed25519');
            key.keyFromPublic(hex.encode(keyBuffer))

            result = key.verify(messageBuffer, hex.encode(signatureBuffer))
        }

        return result
    },

    /**
     * Takes Public Key, Signature and Data and returns if it's valid.
     * @param  {String} PEMCertOrPublicKey - PEM encoded Certificate or Public Key
     * @param  {ArrayBuffer} Signature     - Signature buffer
     * @param  {ArrayBuffer} Data          - Data buffer
     * @return {Boolean}
     */
    'verifySignature': (PEMCertOrPublicKey, Signature, Data) => {
        Signature = Buffer(Signature);
        Data      = Buffer(Data);

        if (asnLen(Signature) != Signature.length)
            throw new Error("checkSignature: signature must be buffer of valid ASN/DER structure.");

        return crypto.createVerify('sha256') // The actual signature alg is ECDSA and determined
            .update(Data)                    // by ASN/DER data in public key. SHA256 is what we set here.
            .verify(PEMCertOrPublicKey, Signature);
    },

    /**
     * Generates random ECDH keypair
     * @return {Buffer} - uncompressed keypair
     */
    'generateP256DHKeys': () => {
        let ecdhBase = crypto.createECDH('prime256v1'); // prime256v1 aka secp256k1 aka NIST P-256 aka P256
        ecdhBase.generateKeys()

        return {
            'private': ecdhBase.getPrivateKey(),
            'public': ecdhBase.getPublicKey()
        }
    },

    /**
     * Takes ECDH PrivateKey and PublicKey, derives shared secret and returns extracted X coefficient of the shared secret Public Key
     * @param  {Buffer} privateKey1 - alices private key buffer uncompressed
     * @param  {Buffer} publicKey2  - bobs public key buffer uncompressed
     * @return {Buffer}             - 32 bytes long X coefficient
     */
    'deriveP256DHSecretsXCoefficient': (privateKey1, publicKey2) => {
        /* Computing shared secret */
        let ecdhBase = crypto.createECDH('prime256v1');
        ecdhBase.setPrivateKey(privateKey1);

        /* Computing PrivK */
        let sharedPrvK = ecdhBase.computeSecret(publicKey2);

        return sharedPrvK
    },

    /**
     * Takes ECDH PrivateKey and derivces PublicKey
     * @param  {Buffer} privateKey - alices private key buffer uncompressed
     * @return {Buffer}
     */
    'deriveP256DHPublicKey': (privateKey) => {
        let ecdhBase = crypto.createECDH('prime256v1');
        ecdhBase.setPrivateKey(privateKey);

        return ecdhBase.getPublicKey()
    },

    /**
     * Generates SHA256-HMAC with the given of the given message buffer
     * @param  {Buffer} keyBuffer 
     * @param  {Buffer} messageBuffer
     * @return {Buffer}
     */
    'generateHMACSHA256': (keyBuffer, messageBuffer) => {
        let hmac = crypto.createHmac('sha256', keyBuffer);
        hmac.update(messageBuffer);

        return hmac.digest('buffer')
    },

    /**
     * Encrypt message with AES256 CBC mode with IV is 0
     * @param  {Buffer} keyBuffer     - key buffer. Must be at least 32 bytes
     * @param  {Buffer} messageBuffer - message buffer
     * @return {Buffer}               - ciphertext buffer
     */
    'encryptAES256CBCIV0': (keyBuffer, messageBuffer) => {
        let zeroIV     = new Buffer(16).fill(0);

        let cipher     = crypto.createCipheriv('aes-256-cbc', keyBuffer, zeroIV);
        let ciphertext = cipher.update(messageBuffer)

        return ciphertext
    },

    /**
     * Decrypts AES256 CBC mode with IV is 0 message
     * @param  {Buffer} keyBuffer        - key buffer. Must be at least 32 bytes
     * @param  {Buffer} ciphertextBuffer - ciphertext buffer
     * @return {Buffer}                  - messageBuffer
     */
    'decryptAES256CBCIV0': (keyBuffer, ciphertextBuffer) => {
        let zeroIV   = new Buffer(16).fill(0);
        let decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, zeroIV);
        decipher.setAutoPadding(false);

        let messageBuffer = decipher.update(ciphertextBuffer);

        return messageBuffer
    },

    /**
     * Generates 2048 bit private/public keypair
     */
    'generateRSA2048KeypairAsync': (alg, hash) => {
        return window.crypto.subtle.generateKey(
            {
                'name': alg,
                'modulusLength': 2048, //can be 1024, 2048, or 4096
                'publicExponent': new Uint8Array([0x01, 0x00, 0x01]),
                'hash': {
                    'name': hash
                },
            },
            true,
            ['sign', 'verify']
        )
        .then((keyPair) => {
            return Promise.all([
                window.crypto.subtle.exportKey('jwk', keyPair.publicKey),
                window.crypto.subtle.exportKey('jwk', keyPair.privateKey)
            ])
        })
        .then((keyPair) => {
            return {
                'public': keyPair[0],
                'private': keyPair[1]
            }
        })
        .catch((err) => {
            throw new Error('Error while generating key. The message is: ' + err)
        })
    },

    /**
     * Sign data with JWK private key
     * @param  {String} alg              - signature algorithm
     * @param  {String} hash             - hash function
     * @param  {Object} privateKeyObject - JWK private key
     * @param  {Buffer} messageBuffer    - message buffer
     * @return {Buffer}                  - signature buffer
     */
    'signWithRSAKeyAsync': (alg, hash, privateKeyObject, messageBuffer) => {
        let saltLength = undefined;
        if(alg.indexOf('PSS') !== -1) {
            if(hash === 'SHA-256') {
                saltLength = 32;
            } else if(hash === 'SHA-384') {
                saltLength = 48;
            } else if(hash === 'SHA-512') {
                saltLength = 64;
            }
        }

        return window.crypto.subtle.importKey('jwk', privateKeyObject, { name: alg, hash: { name: hash }}, false, ['sign'])
            .then((privateKey) => {
                return window.crypto.subtle.sign({ name: alg, saltLength: saltLength }, privateKey, messageBuffer)
            })
            .then((signature) => {
                return new Uint8Array(signature);
            })
    },

    /**
     * Verifies signature
     * @param  {String} alg              - signature algorithm
     * @param  {String} hash             - hash function
     * @param  {Object} privateKeyObject - JWK private key
     * @param  {Buffer} messageBuffer    - message buffer
     * @param  {Buffer} signatureBuffer  - signature buffer
     * @return {Boolean}                 - true/false
     */
    'verifyRSASignatureAsync': (alg, hash, publicKeyObject, messageBuffer, signatureBuffer) => {
        let saltLength = undefined;
        if(alg.indexOf('PSS') !== -1) {
            if(hash === 'SHA-256') {
                saltLength = 32;
            } else if(hash === 'SHA-384') {
                saltLength = 48;
            } else if(hash === 'SHA-512') {
                saltLength = 64;
            }
        }

        return window.crypto.subtle.importKey('jwk', publicKeyObject, { name: alg, hash: { name: hash }}, false, ['verify'])
            .then((publicKey) => {
                return window.crypto.subtle.verify({ name: alg, saltLength: saltLength }, publicKey, signatureBuffer, messageBuffer)
            })
    },

    /**
     * Generates private/public keypair for specified ECDSA algorithm
     * @param  {String} algorithm        - algorithm identifier
     * @return {Object<private, public>} - keypair
     */
    'generateECDSAKeypair': (algorithm) => {
        let ec = new elliptic.ec(algorithm);
        let keypair = ec.genKeyPair();

        let privateKey = keypair.getPrivate('hex');
        let publicKey  = keypair.getPublic('hex');

        return {
            'private': privateKey,
            'public': publicKey
        }
    },

    /**
     * Takes alorithm, privatekey and hash and returns a signature 
     * @param  {String} algorithm  - algorithm identifier
     * @param  {Buffer} keyBuffer  - key buffer
     * @param  {Buffer} hashBuffer - hash buffer
     * @return {Buffer}            - signature buffer 
     */
    'signWithECDSAKeyDER': (algorithm, keyBuffer, hashBuffer) => {
        hashBuffer    = Array.from(hashBuffer);
        let ec        = new elliptic.ec(algorithm);
        let keys      = ec.keyFromPrivate(keyBuffer);

        let signature = keys.sign(hashBuffer);

        return new Uint8Array(signature.toDER())
    },

    /**
     * Takes alorithm, privatekey and hash and returns a signature 
     * @param  {String} algorithm  - algorithm identifier
     * @param  {Buffer} keyBuffer  - key buffer
     * @param  {Buffer} hashBuffer - hash buffer
     * @return {Buffer}            - signature buffer 
     */
    'signWithECDSAKeyANSI': (algorithm, keyBuffer, hashBuffer) => {
        hashBuffer    = Array.from(hashBuffer);
        let ec        = new elliptic.ec(algorithm);
        let keys      = ec.keyFromPrivate(keyBuffer);

        let signature = keys.sign(hashBuffer);
        let r = signature.r.toBuffer();
        let s = signature.s.toBuffer();

        let ansiBuffer = Buffer.concat([r, s]);

        return new Uint8Array(ansiBuffer)
    },

    /**
     * Takes algorithm identifier, keyBuffer, signatureBuffer and messageBuffer and tries to verify signature
     * @param  {String} algorithm       - algorithm identifier
     * @param  {Buffer} keyBuffer
     * @param  {Buffer} signatureBuffer
     * @param  {Buffer} messageBuffer   - A hash of the message
     * @return {Boolean}                - signature can be or cannot be verified              
     */
    'verifyECDSASignature': (algorithm, keyBuffer, signatureBuffer, messageBuffer) => {
        signatureBuffer = Array.from(signatureBuffer);
        messageBuffer   = Array.from(messageBuffer);
        keyBuffer       = Array.from(keyBuffer);

        let ec  = new elliptic.ec(algorithm);
        let key = ec.keyFromPublic(keyBuffer);

        return key.verify(messageBuffer, signatureBuffer)
    },

    /**
     * Generates EdDSA public/private key-pair
     * @return {Object<private, public>} - keypair
     */
    'generateED25519Keypair': () => {
        let ed25519 = new elliptic.eddsa('ed25519');

        let privateKeyBuffer = generateRandomBuffer(32);
        let keyObj = ed25519.keyFromSecret(privateKeyBuffer);
        let publicKeyBuffer = keyObj.getPublic();

        return {
            'private': hex.encode(privateKeyBuffer),
            'public': hex.encode(publicKeyBuffer)
        }
    },

    /**
     * Generates ED25519 signature over given hash
     * @param  {Buffer} key
     * @param  {Buffer} hashBuffer
     * @return {Buffer}
     */
    'signWithED25519Key': (keyBuffer, hashBuffer) => {
        let ed25519   = new elliptic.eddsa('ed25519');
        let keyObj    = ed25519.keyFromSecret(keyBuffer);
        let signature = keyObj.sign(hashBuffer);

        return new Uint8Array(signature.toBytes())
    },

    /**
     * Verifies ED25519 signature
     * @param  {Buffer} keyBuffer
     * @param  {Buffer} signatureBuffer
     * @param  {Buffer} messageBuffer
     * @return {Boolean}
     */
    'verifyED25519Signature': (keyBuffer, signatureBuffer, hashBuffer) => {
        let key = new elliptic.eddsa('ed25519');
        key.keyFromPublic(keyBuffer)

        return key.verify(hashBuffer, signatureBuffer)
    }
}
