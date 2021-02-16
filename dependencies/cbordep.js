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

const cbor = require('cbor');

/**
 * Tries to convert given object to int, otherwise retuns original
 * @param  {Any}     maybeInt
 * @return {Any|Int}
 */
let tryGetIntOrReturnString = (maybeInt) => {
    let result = parseInt(maybeInt);

    if (isNaN(result))
        return maybeInt
    else
        return result
}

/**
 * Returns string of an object type
 * @param  {object} obj - Given object
 * @return {String}     - String value of a type of an object
 */
var type = (obj) => {
    return {}.toString.call(obj)
             .replace(/\[|\]/g, '')
             .split(' ')[1];
}

let sortCBORKeysCTAP2Canonically = (json) => {
    let sortedKeys = [];

    let lengthMap = {};
    for(let key in json) {
        let keyLen = key.length;

        if(!lengthMap[keyLen])
            lengthMap[keyLen] = [];

        lengthMap[keyLen].push(key)
    }

    let sortedLengthKeys = Object
        .keys(lengthMap)
        .map((val) => parseInt(val)) // Parsing INT
        .sort((val1, val2) => val1 - val2) // Sorting descending

    for(let key of sortedLengthKeys) {
        sortedKeys = sortedKeys.concat(lengthMap[key].sort())
    }

    return sortedKeys
}

/**
 * Takes JSON struct and returns a CBOR struct
 * @param  {*} json - any JSON type
 * @return {CBOR}   - CBOR Abstract Structure
 */
let JSONToOBJECTSTRUCT = (json) => {
    if (type(json) === 'Object') {
        let map = new Map();

        let sortedKeys = sortCBORKeysCTAP2Canonically(json);

        for (let key of sortedKeys) {
            if(json[key] !== undefined)
                map.set(tryGetIntOrReturnString(key), JSONToOBJECTSTRUCT(json[key]));
        }

        return map
    }

    if (type(json) === 'Array') {
        let set = new Set();
        for(let item of json) {
            set.add(JSONToOBJECTSTRUCT(item));
        }

        return set
    }

    if(type(json) === 'ArrayBuffer' || type(json).indexOf('Uint') !== -1) {
        if(type(json) !== 'Uint8Array')
            json = convertToUint8Array(json);

        return new Buffer.from(Array.from(json))
    }

    return json
}

let ENFORCEUINT8 = (struct) => {
    if(type(struct) === 'Map') {
        let obj = {};

        for (let key of struct.keys()) {
            obj[key] = ENFORCEUINT8(struct.get(key))
        }

        return obj
    }

    if(type(struct) === 'Object') {
        let obj = {};

        for (let key in struct) {
            obj[key] = ENFORCEUINT8(struct[key])
        }

        return obj
    }

    if (type(struct) === 'Set' || type(struct) === 'Array') {
        let arr = [];

        for (let i of struct) {
            arr.push(ENFORCEUINT8(i));
        }

        return arr
    }

    if(type(struct).indexOf('Uint') !== -1) { 
        return new Uint8Array(Array.from(struct))
    }

    return struct
}

let OBJECTSTRUCTToJSON = (struct, markNonTransportFriendlyFields) => {
    if(type(struct) === 'Map') {
        let obj = {};

        for (let key of struct.keys()) {
            obj[key] = OBJECTSTRUCTToJSON(struct.get(key), markNonTransportFriendlyFields)
        }

        return obj
    }

    if(type(struct) === 'Object') {
        let obj = {};

        for (let key in struct) {
            obj[key] = OBJECTSTRUCTToJSON(struct[key], markNonTransportFriendlyFields)
        }

        return obj
    }

    if (type(struct) === 'Set' || type(struct) === 'Array') {
        let arr = [];

        for (let i of struct) {
            arr.push(OBJECTSTRUCTToJSON(i, markNonTransportFriendlyFields));
        }

        return arr
    }

    let transportPrefix = markNonTransportFriendlyFields ? 'BUFFER' : '';
    /*
     * A magic way to detect native node buffers. Please dont ask cause I don't know why it's like that
     */
    if(type(struct).indexOf('Uint') !== -1 && (struct.byteLength !== struct.buffer.byteLength)) { 
        return transportPrefix + buffAndHex(new Uint8Array(struct))
    }

    if (type(struct) === 'ArrayBuffer' || type(struct).indexOf('Uint') !== -1) {
        return transportPrefix + buffAndHex(convertToUint8Array(struct))
    }

    return struct
}

let buffAndHex = (buffer) => {
    return Buffer.from(Array.from(buffer)).toString('hex')
}

/**
 * Takes CBOR Structure and returns a CBOR Buffer
 * @param  {CBOR}    cborStruct - CBOR Struct
 * @return {Buffer}             - CBOR Buffer
 */
let CBORStructToBuffer = (cborStruct) => {
    return Array.from(cbor.encode(cborStruct))
}

module.exports = {
    /**
     * Takes JSON struct and retuns CBOR encoded ArrayBuffer 
     * @param  {*}           json
     * @return {ArrayBuffer}
     */
    'JSONToCBORArrayBuffer': (json) => {
        let struct = JSONToOBJECTSTRUCT(json);
        let buffer = CBORStructToBuffer(struct);

        return new Uint8Array(buffer)
    },

    'CBORBufferToJSON': (buffer) => {
        let cborHex      = buffAndHex(buffer);
        let objectStruct = cbor.decodeAllSync(cborHex);

        return OBJECTSTRUCTToJSON(objectStruct)
    },
    'CBORBufferToSTRUCT': (buffer) => {
        let cborHex = buffAndHex(buffer);

        return ENFORCEUINT8(cbor.decodeAllSync(cborHex))
    },
    'CBORBufferToNATIVESTRUCT': (buffer) => {
        let cborHex = buffAndHex(buffer);

        return cbor.decodeAllSync(cborHex)
    },
    'CBORBufferToSTRUCTTransportable': (buffer) => {
        let cborHex = buffAndHex(buffer);
        let objectStruct = cbor.decodeAllSync(cborHex);

        return OBJECTSTRUCTToJSON(objectStruct, true)
    },

    'OBJECTSTRUCTToJSON': (struct) => {
        return OBJECTSTRUCTToJSON(struct)
    }
}
