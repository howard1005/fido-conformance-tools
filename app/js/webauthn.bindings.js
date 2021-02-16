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

if(!window.navigator.fido)
    window.navigator.fido = {};

let debufferIterator = (struct) => {
    if (type(struct) === 'Object') {
        let map = {};

        for (let key in struct) {
            if(struct[key] !== undefined)
                map[key] = debufferIterator(struct[key]);
        }

        return map
    }

    if (type(struct) === 'Array') {
        let set = [];
        for(let item of struct) {
            set.push(debufferIterator(item));
        }

        return set
    }

    if(type(struct) === 'String' && /^BUFFER([0-9a-fA-F]{2})+$/.test(struct)) {
        return hex.decode(struct.slice(6))
    }

    return struct
}

let sha1polyfill = (buffer) => {
    return fetch('/crypto/sha1', {
        'method': 'POST',
        'body': JSON.stringify({
            'msg': hex.encode(buffer)
        })
    })
    .then((response) => {
        if(response.status === 200)
            return response.json()

        throw new Error(`Failed to get response from the tool!`);
    })
    .then((response) => {
        if(response.status && response.status !== 'ok')
            throw new Error(`Server returned an error "${response.error}"`);

        return hex.decode(response.digest)
    })
}

window.navigator.fido.webauthn = {
    'decodeToJSON': (cborBuffer) => {
        let cborHex = hex.encode(cborBuffer);

        return fetch('/cbor/decodeToJSON', {
            'method': 'POST',
            'body': cborHex
        })
        .then((response) => {
            if(response.status === 200)
                return response.json()

            throw new Error(`Failed to get response from the tool!`);
        })
        .then((response) => {
            if(response.status && response.status !== 'ok')
                throw new Error(`Server returned an error "${response.error}"`);

            return response
        })
    },

    'decodeToObjectStruct': (cborBuffer) => {
        let cborHex = hex.encode(cborBuffer);

        return fetch('/cbor/decodeToObjectStruct', {
            'method': 'POST',
            'body': cborHex
        })
        .then((response) => {
            if(response.status === 200)
                return response.json()

            throw new Error(`Failed to get response from the tool!`);
        })
        .then((response) => {
            if(response.status && response.status !== 'ok')
                throw new Error(`Server returned an error "${response.error}"`);

            return debufferIterator(response)
        })
    },

    'hash': (func, message) => {
        if(func.toLowerCase().replace('-', '') === 'sha1')
            return sha1polyfill(message)

        return crypto.subtle.digest(func, message)
    },

    'verifySignature': (algorithm, keyPem, signature, message) => {
        let location = '/crypto/verifySignature';
        let key      = keyPem;

        if(algorithm.startsWith('pkcs1')) {
            location = '/crypto/verifyPKCS1Signature'
            let ncoeff = jsrsasign.KEYUTIL.getJWKFromKey(jsrsasign.KEYUTIL.getKey(keyPem)).n;
            key        = hex.encode(base64url.decode(ncoeff));
        }

        return fetch(location, {
            'method': 'POST',
            'body': JSON.stringify({
                'alg': algorithm,
                'key': key,
                'sig': signature,
                'msg': message
            })
        })
        .then((response) => {
            if(response.status === 200)
                return response.json()

            throw new Error(`Failed to get response from the tool!`);
        })
        .then((response) => {
            if(response.status && response.status !== 'ok')
                throw new Error(`Server returned an error "${response.error}"`);

            return response.result
        })
    },

    'verifySignatureCOSE': (key, message, signature) => {
        key       = hex.encode(key);
        signature = hex.encode(signature);
        message   = hex.encode(message);
        return fetch('/crypto/verifySignatureCOSE', {
            'method': 'POST',
            'body': JSON.stringify({
                'key': key,
                'sig': signature,
                'msg': message
            })
        })
        .then((response) => {
            if(response.status === 200)
                return response.json()

            throw new Error(`Failed to get response from the tool!`);
        })
        .then((response) => {
            if(response.status && response.status !== 'ok')
                throw new Error(`Server returned an error "${response.error}"`);

            return response.result
        })
    }
}