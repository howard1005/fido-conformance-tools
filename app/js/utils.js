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

/**
 * Converts any given typed array or arrayBuffer to Uint8
 * @param  {typeObject} obj
 * @return {Uint8Array}
 */
var convertToUint8Array = (obj) => {
    let objectType = type(obj)
    if( objectType != 'Uint8Array' &&
        objectType != 'Uint16Array' &&
        objectType != 'Uint32Array' &&
        objectType != 'ArrayBuffer' )
       throw new TypeError('Only Uint8/16/32Array and ArrayBuffer allowed!')

    if(objectType == 'ArrayBuffer')
        return new Uint8Array(obj.slice())
    else
        return new Uint8Array(obj.buffer.slice())

    return temp
}

/**
 * Creates a new Uint8Array based on two different ArrayBuffers
 *
 * https://gist.github.com/72lions/4528834
 * 
 * @private
 * @param {ArrayBuffer} buffer1 The first buffer.
 * @param {ArrayBuffer} buffer2 The second buffer.
 * @return {ArrayBuffer} The new ArrayBuffer created out of the two.
 */
var mergeArrayBuffersRecursively = (buffer1, buffer2) => {
    if(type(buffer2) == 'Array') {
        if(buffer2.length == 0)
            return buffer1

        buffer2 = mergeArrayBuffersRecursively(buffer2[0], buffer2.slice(1));
    }

    buffer1 = convertToUint8Array(buffer1);
    buffer2 = convertToUint8Array(buffer2);

    let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(buffer1, 0);
    tmp.set(buffer2, buffer1.byteLength);
    return tmp.buffer
}

/**
 * Takes any number of ArrayBuffers and returns merged ArrayBuffer
 * @param * {ArrayBuffer}
 * @return {ArrayBuffer}
 */
var mergeArrayBuffers = function() {
    let args = Array.prototype.slice.call(arguments);
    if(args.length < 2)
        throw new Error('Minimum number of arguments is two!');

    for(let i = 0; i <  args.length; i++) {
        if(!isTypedArray(args[i]))
            throw new Error(`The argument number number ${i} is not TypedArray! The argument value is ${args[i]}`);
    }

    return convertToUint8Array(mergeArrayBuffersRecursively(args[0], args.slice(1)))
}

/**
 * Takes arbitrary buffer and returns integer.
 * @param  {ArrayBuffer} buffer
 * @return {Integer}
 */
var arrayBufferToInt = (buffer) => {
    buffer = convertToUint8Array(buffer).buffer;

    if(buffer.byteLength === 1)
        return new Int8Array(buffer)[0];
    else if(buffer.byteLength === 2)
        return new Int16Array(buffer)[0];
    else
        return new Int32Array(buffer)[0];
}

/**
 * Takes arbitrary integer number, and returns byte array of it
 * @param  {Number} num
 * @return {Uint8Array}
 */
var numberToArrayBuffer = (num) => {
    if(type(num) !== 'Number')
        throw new TypeError('The argument "num" expected to be a number!')

    let byteArray = [];

    let numberByteSize = Math.ceil(Math.log2(num) / 8);
    for(let i = 0; i < numberByteSize; i++)
        byteArray.push((num >> 8 * i) & 0xff)

    return new Uint8Array(byteArray)
}

/**
 * Takes arbitrary buffer and returns decoded string.
 * @param  {ArrayBuffer} buffer
 * @return {Integer}
 */
var arrayBufferToString = (buffer) => {
    return new TextDecoder('UTF-8').decode(buffer);
}

/**
 * Takes arbitrary string and returns array buffer
 * @param  {String}       str - arbitrary string
 * @return {ArrayBuffer}      - array buffer
 */
var stringToArrayBuffer = (str) => {
    return new TextEncoder('utf-8').encode(str);
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

/**
 * Returns if data is valid, and error messages
 * @param  {Object} schema - schema to validate against
 * @param  {Object} data   - data to validate
 * @return {Object}        - object.valid - true/false. object.errorMessages - string
 */
var validateDataAgainstScheme = (data, scheme) => {
    scheme.id = `${config.baseURL}schemes/StrangeFix${Math.random().toString(36).substring(7)}.scheme.json`;

    let validate = ajv.compile(scheme);
    let valid = validate(data);

    let errorMessages = ''

    if(!valid) {
        errorMessages = '\n\n'
        for(let error of validate.errors) {
            errorMessages += `INVALID_TRANSACTION_CONTENT: ${error.message}\n`
        }
        errorMessages += '\n'
    }

    console.log(validate.errors);

    return {
        valid,
        errorMessages,
        'errorObject': validate.errors
    }
}

/**
 * Decodes GET parameters
 * @param  {String} qs - document.location.search
 * @return {Object}    - get parameters dictionary
 */
var getQueryParams = (qs) => {
    qs = qs.split('+').join(' ');

    let params = {};
    let tokens;
    let re = /[?&]?([^=]+)=([^&]*)/g;

    while(tokens = re.exec(qs))
        params[decodeURIComponent(tokens[1])] = decodeURIComponent(tokens[2]);

    return params;
}

/**
 * Takes object, and returns if it is typed array
 * @param  {Any}     obj
 * @return {Boolean}
 */
var isTypedArray = (obj) => {
    return type(obj) === 'ArrayBuffer' || type(obj).indexOf('Uint') !== -1
}

/**
 * UTF-8 Base64URL encoder
 * @param  {String} str - string to encode
 * @return {String}     - base64url encoded data
 */
var UTF8ToB64URL = (str) => {
    let output = window
                    .btoa(unescape(encodeURIComponent(str)))
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/\=/g, '');

    return output
}

/**
 * Base65URL UTF-8 decoder
 * @param  {String} str - Base64URL encoded data
 * @return {String}     - UTF-8 decoded data
 */
var B64URLToUTF8 = (str) => {
    let input = str
                .replace(/\-/g, '+')
                .replace(/\_/g, '/');

    return decodeURIComponent(escape(window.atob(input)));
}

/**
 * Takes any given UTF8 string, and converts it to buffer
 * @param  {String} str - any given string
 * @return {Buffer}     - buffer of the string
 */
var UTF8toBuffer = (str) => {
    let b64url = UTF8ToB64URL(str);

    return base64url.decode(b64url)
}

/**
 * Converts hex to base64
 * @param  {String} hexString - hex string
 * @return {String}           - base64 string
 */
var HEXToBASE64 = (hexString) => {
    let buffer = hex.decode(hexString)
    return base64.encode(buffer);
}

/**
 * Generate secure random string
 * @param  {Number} len - Length of the string(default 20 char)
 * @return {String}     - random string
 */
var generateRandomString = (len) => {
    len = len || 20;

    let randomStringBuffer = new Uint8Array(len);
    window.crypto.getRandomValues(randomStringBuffer);
    let result = base64url.encode(randomStringBuffer);

    return result.substr(0, len);
}

/**
 * Generate secure random buffer
 * @param  {Number} len - Length of the buffer (default 32 bytes)
 * @return {Uint8Array} - random string
 */
var generateRandomBuffer = (len) => {
    len = len || 32;

    let randomBuffer = new Uint8Array(len);
    window.crypto.getRandomValues(randomBuffer);

    return randomBuffer
}

/**
 * Returns inverse of a given object
 * @param  {Object} dict - given object
 * @return {Object}      - inverse of an object
 */
var inverseDictionary = (dict) => {
    let inverse = {};

    for(let key in dict)
        inverse[dict[key]] = tryGetIntOrReturnOriginal(key);

    return inverse
}

/**
 * Takes arbitrary string, and encodes it in Base64URL with no padding
 * @param  {String} str - given string
 * @return {String}     - Base64URL encoded string
 */
var stringToBase64URL = (str) => {
    return base64url.encode(stringToArrayBuffer(str))
}

/**
 * Takes arbitrary Base64URL string, and decodes it
 * @param  {String} str - Base64URL encoded string
 * @return {String}     - Decoded string
 */
var base64URLToString = (str) => {
    return arrayBufferToString(base64url.decode(str))
}

/**
 * Takes JSON object and returns base64url encoded JSON string
 * @param  {Object} obj - JSON Object
 * @return {String}
 */
var JSONToBase64URL = (obj) => {
    let str = JSON.stringify(obj);
    return stringToBase64URL(str)
}

/**
 * Takes arbitrary object, and returns copy of it.
 * @param  {Object} obj - given object
 * @return {Object}     - a copy
 *
 * Ref: https://stackoverflow.com/questions/122102/what-is-the-most-efficient-way-to-deep-clone-an-object-in-javascript
 */
var cloneObject = (obj) => {
    return JSON.parse(JSON.stringify(obj))
}

/**
 * Takes arbitrary URL and returns accessible URL object
 * @param  {String} url - arbitrary URL
 * @return {Object}     - URL object
 */
var breakURL = (url) => {
    let args = url.split(/^((https?):\/\/)?([^:^\/]*):?(\d*)?(.*)?/);
    return {
        'protocol': args[2] + ':',
        'host'    : args[3] || '',
        'port'    : args[4] || '',
        'path'    : args[5] || '/',
        'origin'  : `${args[2]}://${args[3]}${args[4] ? ':' + args[4] : ''}`
    }
}

/**
 * Takes metadata attestationCertificate string and returns PEM formated certificate string
 * @param  {String} cert - attestationCertificate
 * @return {String}      - PEM formated attestationCertificate
 */
var base64StringCertToPEM = (cert) => {
    let PEMCert = '';

    for(let i = 0; i < Math.ceil(cert.length / 64); i++) {
        let start = 64 * i;

        PEMCert += cert.substr(start, 64) + '\n';
    }

    PEMCert = '-----BEGIN CERTIFICATE-----\n' + PEMCert + '-----END CERTIFICATE-----';

    return PEMCert;
}

/**
 * Takes base64url encoded certificate, and returns valid PEM
 * @param  {String} certificate - base64url cert
 * @return {String}             - base64 pem
 */
var base64urlCertToPem = (certificate) => {
    let buffer     = base64url.decode(certificate);
    let base64cert = base64.encode(buffer);

    return base64StringCertToPEM(base64cert);
}

/**
 * Takes a PEM encoded certificate chain array and verifies it
 * @param  {String[]} certificates - PEM certificate chain
 * @return {Boolean}               - Returns if certificate chain can be validated
 */
var verifyCertificateChain = (certificates) => {
    let valid = true;

    if(certificates.length === 0)
        throw new Error('Empty certificate path!');


    if(hasDuplicates(certificates))
        throw new Error('Certificate path contains dublicate certificates! Please check that authenticator does not return full chain it its response!');

    for(let i = 0; i < certificates.length; i++) {
        let Cert        = certificates[i];
        let certificate = new jsrsasign.X509();
        certificate.readCertPEM(Cert);

        let CACert = '';
        if(i + 1 >= certificates.length) {
            CACert = Cert;
        } else if(certificate.getSubjectString() !== certificate.getIssuerString()) { // If only intermediate given
            if(certificate.length === 1)
                return false
            
            break
        } else {
            CACert = certificates[i + 1];
        }

        let certStruct   = jsrsasign.ASN1HEX.getTLVbyList(certificate.hex, 0, [0]);
        let algorithm    = certificate.getSignatureAlgorithmField();
        let signatureHex = certificate.getSignatureValueHex()

        // Verify against CA
        let Signature = new jsrsasign.crypto.Signature({alg: algorithm});
        Signature.init(CACert);
        Signature.updateHex(certStruct);
        valid = valid && Signature.verify(signatureHex); // true if CA signed the certificate
    }

    return valid
}

/**
 * Returns what endian system does system use
 * @return {String} big/little
 */
var getEndian = () => {
    let arrayBuffer = new ArrayBuffer(2);
    let uint8Array = new Uint8Array(arrayBuffer);
    let uint16array = new Uint16Array(arrayBuffer);
    uint8Array[0] = 0xAA; // set first byte
    uint8Array[1] = 0xBB; // set second byte

    if(uint16array[0] === 0xBBAA)
        return 'little';

    if(uint16array[0] === 0xAABB)
        return 'big';

    else
        throw new Error('Something crazy just happened!');
}

/**
 * Takes item and array and returns if an item is a member of an array
 * @param  {Array} arr  - an array
 * @param  {Any}   item - any object
 * @return {Boolean}    - true if item is a member, false if not
 */
var arrayContainsItem = (arr, item) => {
    if (type(arr) !== 'Array')
        throw new Error(`Can not index non-array object. Expected ${arr} to be an array!`);

    return arr.indexOf(item) !== -1
}

/**
 * Tries to convert given object to int, otherwise retuns original
 * @param  {Any}     maybeInt
 * @return {Any|Int}
 */
var tryGetIntOrReturnOriginal = (maybeInt) => {
    try {
        let result = parseInt(maybeInt);

        if(!isNaN(result))
            return result
        else 
            return maybeInt
    } catch(e) {
        return maybeInt
    }
}

/**
 * Generates random buffer with ensured ending not being 00
 * @param  {Number} length
 * @return {Buffer}
 */
var generateRandomClientPinBuffer = (length) => {
    let buff = generateRandomBuffer(length);
    buff[buff.length - 1] = 0x42;

    return buff
}

/**
 * Takes arrayBuffer/Uint*Arrays and ensure that it is BigEndian encoded
 * @param  {TypedArray} buff
 * @return {Uint8Array}      - BigEndian encoded typedArray
 */
var getBigEndianEcoding = (buff) => {
    buff = convertToUint8Array(buff);

    if (getEndian() === 'big')
        return buff
    else
        return buff.reverse()
}

/**
 * Takes 2byte buffer, and decodes it to BingEndian 16bit integer
 * @param  {TypedArray} buffer
 * @return {Number}
 */
var readBE16 = (buffer) => {
    buffer = convertToUint8Array(buffer);

    if(buffer.length !== 2)
        throw new Error('Only 2byte buffer allowed!');

    buffer = getBigEndianEcoding(buffer);

    return new Uint16Array(buffer.buffer)[0]
}

/**
 * Takes 4byte buffer, and decodes it to BingEndian 32bit integer
 * @param  {TypedArray} buffer
 * @return {Number}
 */
var readBE32 = (buffer) => {
    buffer = convertToUint8Array(buffer);

    if(buffer.length !== 4)
        throw new Error('Only 4byte buffers allowed!');

    buffer = getBigEndianEcoding(buffer);

    return new Uint32Array(buffer.buffer)[0]
}

/**
 * Returns a random integer between min (inclusive) and max (inclusive)
 * @param  {Number} min - min integer
 * @param  {Number} max - max integer
 * @return {Number}     - random integer
 */
var generateSecureRandomInt = (min, max) => {
    /* FROM https://stackoverflow.com/a/34577886 */
    // A buffer with just the right size to convert to Float64
    let buffer = new ArrayBuffer(8);

    // View it as an Int8Array and fill it with 8 random ints
    let ints = new Int8Array(buffer);
    window.crypto.getRandomValues(ints);

    // Set the sign (ints[7][7]) to 0 and the
    // exponent (ints[7][6]-[6][5]) to just the right size 
    // (all ones except for the highest bit)
    ints[7] = 63;
    ints[6] |= 0xf0;

    // Now view it as a Float64Array, and read the one float from it
    let float = new DataView(buffer).getFloat64(0, true) - 1; 

    return Math.floor(float * (max - min + 1)) + min;
}

/**
 * Takes arbitrary number pads it to the requested length
 * 78152, 6 -> 078152
 * @param  {Number} number
 * @param  {Number} wantedLength
 * @return {String} 
 */
var leftpad = (number, wantedLength) => {
    number = String(number);
    let needsZeroes = wantedLength - number.length;
    for(let i = 0; i < needsZeroes && i >= 0; i++) {
        number = '0' + number
    }

    return number
}

/**
 * Returns an object of a random type
 * @param  {String} exceptType - what type to exclude from generation
 * @return {Any}
 */
var generateRandomTypeExcluding = (exceptType, exceptType2) => {
    let types = ['object', 'array', 'number', 'string', 'boolean']
    types = types.filter((item) => { return item !== exceptType })
    types = types.filter((item) => { return item !== exceptType2 })

    let randomIndex  = generateSecureRandomInt(0, types.length - 1);
    let selectedType = types[randomIndex];

    switch(selectedType) {
        case 'object':
            return {}
        break
        case 'array':
            return []
        break
        case 'number':
            return generateSecureRandomInt(0, 16657)
        break
        case 'string':
            return generateRandomString()
        break
        case 'boolean':
            return !!generateSecureRandomInt(0, 1)
        break
    }
}

/**
 * Generate new Uint8Array of the specified length and filled with zeroes
 * @param  {Number} len - length of the buffer
 * @return {Buffer}
 */
var generateZeroBuffer = (len) => {
    len = len || 64;

    return new Uint8Array(len).map(() => 0)
}

/**
 * Generate new Uint8Array of the specified length and filled with 0xEE
 * @param  {Number} len - length of the buffer
 * @return {Buffer}
 */
var generatePaintedBuffer = (len) => {
    len = len || 64;

    return new Uint8Array(len).map(() => 0xEE)
}

/**
 * Returns base64url encoded specified amount of random bytes
 * @param  {Number} len - Length of a buffer
 * @return {String}     - Base64URL encoded random bytes
 */
var generateRandomBase64urlBytes = (len) => {
    len = len || 32;

    let randomBuffer = new Uint8Array(len);
    window.crypto.getRandomValues(randomBuffer);

    return base64url.encode(randomBuffer)
}

/**
 * Returns random AAID
 * @return {String}
 */
var generateRandomAAID = () => {
    let vendorID  = generateRandomBuffer(2);
    let versionID = generateRandomBuffer(2);

    return `${hex.encode(vendorID).toUpperCase()}#${hex.encode(versionID).toUpperCase()}`
}

/**
 * Returns randomly selected name from a list
 * @return {String}
 */
var generateRandomName = () => {
    let names = ['Aleisha Neyman', 'Freddie Montijo', 'Xavier Matis', 'Louie Houtz', 'Julianna Hollman', 'Rosalia Jarret', 'Star Euell', 'Katelynn Dunmore', 'Stasia Britain', 'Eleanor Duchene', 'Bennie Moneypenny', 'Shenika Olin', 'Tamara Tineo', 'Marleen Lafontaine', 'Marivel Placencia', 'Sharda Manier', 'Latosha Sabatini', 'Dylan Wayne', 'Stanford Mcguffie', 'Angel Plaza', 'Tona Dandridge', 'Tony Alber', 'Domitila Headen', 'Lucrecia Grenz', 'Clarice Zemlicka', 'Donetta Lukasiewicz', 'Leona Grayson', 'Christena Yoshimura', 'Latashia Lanoue', 'Lu Hopps', 'Christiana Muntz', 'Johnetta Papa', 'Lora Chasse', 'Josiah Turman', 'Shala Dull', 'Alec Palazzo', 'Sharyl Seguin', 'Taren Gatewood', 'Gretchen Mo', 'Lakeesha Hemstreet', 'Marcelle Ritchie', 'Deandra Sauer', 'Nannie Fenner', 'Victor Callaway', 'Tyrell Castro', 'Rosamond Carron', 'Megan Vinzant', 'Gertrud Fridley', 'Mozell Shue', 'Kanisha Vanmeter', 'Commander Shepard', 'Bilbo Baggins', 'Peregrin Tuk']

    let randomIndex  = generateSecureRandomInt(0, names.length - 1);
    
    return names[randomIndex]
}

var generateRandomIdentity = () => {
    let name     = generateRandomName();
    let domain   = generateRandomDomain();

    let username = undefined;
    if(generateSecureRandomInt(0, 1))
        username = name.replace(/\s/, '').toLowerCase()
    else
        username = name.replace(/\s/, '.').toLowerCase()

    let email    = generateRandomDomain();
    let password = generateRandomString();

    return {email, password}
}

/**
 * Returns random email address on the random domain
 * @return {String}
 */
var generateRandomEmail = () => {
    let name   = generateRandomName();
    let domain = generateRandomDomain();
    return generateEmailFromNameAndDomain(name, domain)
}

/**
 * Takes a name, and returns a random email from name and domain
 * @param  {String} name [description]
 * @return {String}      [description]
 */
var generateEmailFromNameAndDomain = (name, domain) => {
    let base = '';
    if(generateSecureRandomInt(0, 1))
        base = name.replace(/\s/, '').toLowerCase()
    else
        base = name.replace(/\s/, '.').toLowerCase()

    return `${base}@${domain}`
}

/**
 * Generates a random domain name
 * @return {String}
 */
var generateRandomDomain = () => {
    let domain = `${generateRandomWord()}${generateRandomWord()}`;

    let randomIndex = generateSecureRandomInt(0, listOfCountryCodes.length - 1);
    let zone = listOfCountryCodes[randomIndex]

    return `${domain}.${zone}`.toLowerCase()
}

/**
 * Returns a list of the random indexes
 * @param  {Number} size
 * @return {Array<Number>}
 */
var generateListOfRandomIndexes = (size) => {
    let arr = [];

    for(let i = 0; i < size; i++)
        arr.push(i)

    for(let i = size - 1; i >= 0; i--){
        let temp = arr[i];
        let randomIndex = generateSecureRandomInt(0, size - 1);

        arr[i] = arr[randomIndex];
        arr[randomIndex] = temp        
    }

    return arr
}

/**
 * Returns a random word
 * @return {String}
 */
var generateRandomWord = () => {
    let words = ['plum', 'lemon', 'huckleberry', 'pear', 'lime', 'mango', 'coconut', 'jujube', 'dragonfruit', 'blackberry', 'starfruit', 'kiwi', 'kumquat', 'clementine', 'orange', 'passonfruit', 'avocado', 'guava', 'grapefruit', 'apple', 'blueberry', 'cherry', 'boysenberry', 'strawberry', 'papaya', 'nectarine', 'peach', 'cantaloupe', 'satsuma', 'raspberry', 'apricot', 'pineapple', 'grape', 'tomato', 'honeydew', 'watermelon', 'date', 'tangerine', 'banana', 'fig', 'pomegranate', 'porter', 'door', 'number', 'didactic', 'back', 'unaccountable', 'unfasten', 'poised', 'vague', 'tumble', 'obedient', 'thoughtless', 'swanky', 'burst', 'double', 'yam', 'motion', 'pin', 'level', 'mute', 'order', 'shame', 'impulse', 'death', 'murky', 'type', 'gather', 'abhorrent', 'industrious', 'legs', 'connection', 'magnificent', 'voyage', 'brake', 'wide', 'choke', 'wait', 'fancy', 'eyes', 'unit', 'elderly', 'nest', 'spiritual', 'spark', 'disgusting', 'excuse', 'teaching', 'hook', 'island', 'disapprove', 'hapless', 'scintillating', 'noiseless', 'switch', 'irate', 'close', 'milky', 'messup', 'mighty', 'guide', 'straw', 'warm', 'bird', 'soothe', 'hair', 'fork', 'shiny', 'distribution', 'found', 'smart', 'aloof', 'scratch', 'loose', 'flame', 'skirt', 'cycle', 'wilderness', 'society', 'relation', 'helpless', 'successful', 'wrap', 'pine', 'whispering', 'bouncy', 'communicate', 'previous', 'table', 'dinner', 'cause', 'spurious', 'squeamish', 'windy', 'grab', 'rejoice', 'extend', 'mix', 'afford', 'blue-eyed', 'children']

    let randomIndex  = generateSecureRandomInt(0, words.length - 1);
    
    return words[randomIndex]
}

/**
 * List of official ISO Alpha2 codes
 * @type {Array}
 */
var listOfCountryCodes = ['AF', 'AX', 'AL', 'DZ', 'AS', 'AD', 'AO', 'AI', 'AQ', 'AG', 'AR', 'AM', 'AW', 'AU', 'AT', 'AZ', 'BS', 'BH', 'BD', 'BB', 'BY', 'BE', 'BZ', 'BJ', 'BM', 'BT', 'BO', 'BA', 'BW', 'BV', 'BR', 'IO', 'BN', 'BG', 'BF', 'BI', 'KH', 'CM', 'CA', 'CV', 'KY', 'CF', 'TD', 'CL', 'CN', 'CX', 'CC', 'CO', 'KM', 'CG', 'CD', 'CK', 'CR', 'CI', 'HR', 'CU', 'CY', 'CZ', 'DK', 'DJ', 'DM', 'DO', 'EC', 'EG', 'SV', 'GQ', 'ER', 'EE', 'ET', 'FK', 'FO', 'FJ', 'FI', 'FR', 'GF', 'PF', 'TF', 'GA', 'GM', 'GE', 'DE', 'GH', 'GI', 'GR', 'GL', 'GD', 'GP', 'GU', 'GT', 'GG', 'GN', 'GW', 'GY', 'HT', 'HM', 'VA', 'HN', 'HK', 'HU', 'IS', 'IN', 'ID', 'IR', 'IQ', 'IE', 'IM', 'IL', 'IT', 'JM', 'JP', 'JE', 'JO', 'KZ', 'KE', 'KI', 'KR', 'KW', 'KG', 'LA', 'LV', 'LB', 'LS', 'LR', 'LY', 'LI', 'LT', 'LU', 'MO', 'MK', 'MG', 'MW', 'MY', 'MV', 'ML', 'MT', 'MH', 'MQ', 'MR', 'MU', 'YT', 'MX', 'FM', 'MD', 'MC', 'MN', 'ME', 'MS', 'MA', 'MZ', 'MM', 'NA', 'NR', 'NP', 'NL', 'AN', 'NC', 'NZ', 'NI', 'NE', 'NG', 'NU', 'NF', 'MP', 'NO', 'OM', 'PK', 'PW', 'PS', 'PA', 'PG', 'PY', 'PE', 'PH', 'PN', 'PL', 'PT', 'PR', 'QA', 'RE', 'RO', 'RU', 'RW', 'BL', 'SH', 'KN', 'LC', 'MF', 'PM', 'VC', 'WS', 'SM', 'ST', 'SA', 'SN', 'RS', 'SC', 'SL', 'SG', 'SK', 'SI', 'SB', 'SO', 'ZA', 'GS', 'ES', 'LK', 'SD', 'SR', 'SJ', 'SZ', 'SE', 'CH', 'SY', 'TW', 'TJ', 'TZ', 'TH', 'TL', 'TG', 'TK', 'TO', 'TT', 'TN', 'TR', 'TM', 'TC', 'TV', 'UG', 'UA', 'AE', 'GB', 'US', 'UM', 'UY', 'UZ', 'VU', 'VE', 'VN', 'VG', 'VI', 'WF', 'EH', 'YE', 'ZM', 'ZW']

/**
 * Takes arbitrary string and checks if it's a valid base64 string
 * @param  {String}  str
 * @return {Boolean}
 */
var isValidBase64String = (str) => {
    let regex = /^[A-Za-z0-9+\/]+={0,3}$/;

    return regex.test(str)
}

/**
 * Takes arbitrary string and checks if it's a valid base64url string
 * @param  {String}  str
 * @return {Boolean}
 */
var isValidBase64URLString = (str) => {
    let regex = /^[A-Za-z0-9-_]+$/;

    return regex.test(str)
}

/**
 * Tries to parse JSON, and if error occurs returns more frendly error 
 * @param  {String} jsonString - JSON
 * @return {Object}            - JS object
 */
var tryDecodeJSON = (jsonString) => {
    try {
        return JSON.parse(jsonString)
    } catch(e) {
        throw new Error(`Error while decoding JSON string. Parser returned error: ${e}. Test your JSON at https://jsonlint.com/`)
    }
}

/**
 * Returns a Date object that is set to 5 years in the future from now.
 * @return {Date} - date in five years
 */
var getDateIn5Years = () => {
    let currentDate = new Date();
    return new Date(currentDate.getFullYear() + 5, currentDate.getMonth(), currentDate.getDay())
}

/**
 * Takes generalizedTime or UTC time string and returns DATE object.
 * @param  {String} dateString
 * @return {Date}
 */
var stringTimeToDate = (dateString) => {
    if(dateString.length === 13) 
        return new Date(`20${dateString.slice(0, 2)}-${dateString.slice(2, 4)}-${dateString.slice(4, 6)} ${dateString.slice(6, 8)}:${dateString.slice(8, 10)}:${dateString.slice(10, 12)} GMT`)
    else
        return new Date(`${dateString.slice(0, 4)}-${dateString.slice(4, 6)}-${dateString.slice(6, 8)} ${dateString.slice(8, 10)}:${dateString.slice(10, 12)}:${dateString.slice(12, 14)} GMT`)
}

/**
 * Takes kjur x509 cert, and return js object dictionary
 * @param  {Object} kjurX509Cert - kjur x509 object
 * @return {Object}              - js object dict
 */
var getCertificateInfoObject = (kjurX509Cert) => {
    let infoObject = {};

    /* Issuing params */
    try {
        let issuerString    = kjurX509Cert.getSubjectString();
        let issuerParamsStr = issuerString.split('/').filter((str) => str != '');
        for(let param of issuerParamsStr) {
            let paramKeys = param.split('=');
            infoObject[paramKeys[0]] = paramKeys[1];
        }
    } catch(e) {}

    /* Version */
    infoObject.version = kjurX509Cert.version;

    /* Dates */
    let nbs = kjurX509Cert.getNotBefore();
    infoObject.notBefore = stringTimeToDate(nbs)

    let nas  = kjurX509Cert.getNotAfter();
    infoObject.notAfter = stringTimeToDate(nas)

    infoObject.basicConstraintsCA = !!kjurX509Cert.getExtBasicConstraints().cA;

    return infoObject
}

/**
 * Takes metadata attestationCertificate string and returns PEM formated certificate string
 * @param  {String} cert - attestationCertificate
 * @return {String}      - PEM formated attestationCertificate
 */
var metadataAttestationCertToPEM = (cert) => {
    let PEMCert = '';

    for(let i = 0; i < Math.ceil(cert.length / 64); i++) {
        let start = 64 * i;

        PEMCert += cert.substr(start, 64) + '\n';
    }

    PEMCert = '-----BEGIN CERTIFICATE-----\n' + PEMCert + '-----END CERTIFICATE-----';

    return PEMCert;
}

/**
 * Takes base64url encoded certificate, and returns valid PEM
 * @param  {String} certificate - base64url cert
 * @return {String}             - base64 pem
 */
var base64urlCertToPem = (certificate) => {
    let buffer = base64url.decode(certificate);
    let base64cert = base64.encode(buffer);

    return metadataAttestationCertToPEM(base64cert);
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {ArrayBuffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
var ASN1toPEM = (buffer) => {
    buffer = convertToUint8Array(buffer)
    let type;
    if (buffer.length == 65 && buffer[0] == 0x04) {
        // If needed, we encode rawpublic key to ASN structure, adding metadata:
        // SEQUENCE {
        //   SEQUENCE {
        //      OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
        //      OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
        //   }
        //   BITSTRING <raw public key>
        // }
        // Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        
        buffer = new Uint8Array(mergeArrayBuffers(hex.decode('3059301306072a8648ce3d020106082a8648ce3d030107034200'), buffer));

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = base64.encode(buffer);

    let PEMCert = '';
    for(let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMCert += b64cert.substr(start, 64) + '\n';
    }

    PEMCert = '-----BEGIN ' + type + '-----\n' + PEMCert + '-----END ' + type + '-----\n';
    
    return PEMCert;
}

/**
 * Returns if authenticator is a silent authenticator
 * @return {Boolean}
 */
var isSilentAuthenticator = () => {
    for(let uvd of window.config.test.metadataStatement.userVerificationDetails) {
        for(let uv of uvd) {
           if(uv.userVerification === USER_VERIFICATION_METHODS_TO_INT.USER_VERIFY_NONE) {
                return true
            } 
        }
    }

    return false
}

/**
 * Checks that userVerificationDetails contains userVerification
 * @param  {Array} userVerificationDetails
 * @param  {Number} userVerification
 * @return {Boolean}
 */
var userVerificationDetailsContains = (userVerificationDetails, userVerification) => {
    for(let uvd of userVerificationDetails) {
        for(let uvc of uvd) {
            if(uvc.userVerification === userVerification)
                return true
        }
    }

    return false
}

/**
 * Returns a list of user verification AND combos
 * @return {Array<Number>}
 */
var getMetadataUserVerificationCombos = () => {
    let uvd = window.config.test.metadataStatement.userVerificationDetails;
    
    if(!uvd)
        throw new Error('Metadata missing "userVerificationDetails" field!');

    let combos = [];
    for(let uvor of uvd) {
        let userVerificationCombo = 0;
        for(let uvand of uvor)
            userVerificationCombo += uvand.userVerification;

        combos.push(userVerificationCombo);
    }

    return combos
}

/**
 * Checks that Metadata.userVerificationDetails contains any UV of userVerifications list
 * @param  {Array} userVerificationDetails
 * @param  {Array} userVerifications - list of user verifications
 * @return {Boolean}
 */
var metadataUserVerificationDetailsContainsAnyOf = (userVerifications) => {
    let uvd = window.config.test.metadataStatement.userVerificationDetails;

    if(!uvd)
        throw new Error('Metadata missing "userVerificationDetails" field!');

    for(let uv of userVerifications) {
        if(userVerificationDetailsContains(uvd, uv))
            return true
    }

    return false
}

/**
 * Takes userVerificationDetails, and returns a list of available userVerifications
 * @param  {Array} userVerificationDetails - userVerificationDetails
 * @return {Array}                         - list of available userVerifications
 */
var getListOfAvailableUserVerifications = (userVerificationDetails) => {    
    let list = [];
    for(let uvor of userVerificationDetails) {
        for(let uvand of uvor) {
            if(!arrayContainsItem(list, uvand.userVerification))
                list.push(uvand.userVerification)
        }
    }

    return list
}

/**
 * Returns promise that fails with given Error object with specified error message
 * @param  {String}  errorMessage - Am... Error messsage I guess
 * @return {Promise}
 */
var ErrorPromise = (errorMessage) => {
    return new Promise((resolve, reject) => {
        reject(new Error(errorMessage.toString()))
    })
}

/**
 * Takes promise, and inverses it. So it rejects if succeeds, and resolve if fails
 * @param  {Promise} promise
 * @return {Promise}
 */
var expectPromiseToFail = (promise) => {
    return new Promise((resolve, reject) => {
        promise
            .then((success) => reject('Promise succeded when expected to fail!'))
            .catch((fail)   => {
                console.log('Authenticator successfully returned an error: ', fail)
                resolve(fail)
            })
    })
}

/**
 * Returns promise that resolves in "timeout" seconds
 * @param  {Number}  timeout
 * @return {Promise}
 */
var TimeoutPromise = (timeout) => {
    timeout = timeout || 1000;
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve()
        }, timeout)
    })
}

/**
 * Takes 16 byte AAGUID buffer, and converts to correct RFC format
 * @param  {Buffer} buffer
 * @return {String}
 */
var aaguidBufferToString = (buffer) => {
    if(buffer.length != 16)
        throw new Error('AAGUID buffer must be 16 bytes long!');

    let hexaaguid = hex.encode(buffer);
    let aaguid    = `${hexaaguid.slice(0, 8)}-${hexaaguid.slice(8, 12)}-${hexaaguid.slice(12, 16)}-${hexaaguid.slice(16, 20)}-${hexaaguid.slice(20)}`;

    return aaguid
}

/**
 * Returns selected device getInfo.
 * @return {GetInfo}
 */
var getDeviceInfo = () => {
    return window.config.test.fidoauthenticator;
}

/**
 * Returns vendor provided metadata statement
 * @return {Object}
 */
var getMetadataStatement = () => {
    return window.config.test.metadataStatement;
}

/**
 * Checks if a given array contains dublicates
 * @param  {Array}   array
 * @return {Boolean}
 */
var hasDuplicates = (array) => {
    return (new Set(array)).size !== array.length;
}

/**
 * Checks if metadata contains extension ID 
 * @param  {String} extensionId
 * @return {Boolean}
 */
var metadataContainsExtension = (extensionId) => {
    let metadata = getMetadataStatement();

    if(!metadata.supportedExtensions)
        return false

    for(let extension of metadata.supportedExtensions)
        if(extension.id === extensionId)
            return true

    return false
}

/**
 * Returns random transaction confirmation text
 * @return {String}
 */
var generateRandomTransactionText = () => {
    return `Are you sure you want to send ${generateSecureRandomInt(50, 1000)}$ to ${generateRandomName()}?`;
}

var jsonClone = (obj) => {
    return JSON.parse(JSON.stringify(obj))
}

var hexifyInt = (num) => {
    return '0x' + num.toString(16)
}
