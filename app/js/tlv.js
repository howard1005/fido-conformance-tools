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
    'use strict';

/* ----- UTILS ----- */
    /**
     * Returns inverse of a given object
     * @param  {Object} dict - given object
     * @return {Object}      - inverse of an object
     */
    let inverseDictionary = (dict) => {
        let inverse = {};

        for(let key in dict)
            inverse[dict[key]] = key;

        return inverse
    }

    /**
     * Returns string of an object type
     * @param  {object} obj - Given object
     * @return {String}     - String value of a type of an object
     */
    let type = (obj) => {
        return {}.toString.call(obj)
                 .replace(/\[|\]/g, '')
                 .split(' ')[1];
    }

    /**
     * Converts any given typed array or arrayBuffer to Uint8
     * @param  {typeObject} obj
     * @return {Uint8Array}
     */
    let convertToUint8Array = (obj) => {
        let objectType = type(obj)
        if( objectType != 'Uint8Array' &&
            objectType != 'Uint16Array' &&
            objectType != 'Uint32Array' &&
            objectType != 'ArrayBuffer' )
            throw new TypeError('Only Uint8/16/32Array and ArrayBuffer allowed!')

        if(objectType == 'ArrayBuffer')
            return new Uint8Array(obj)
        else
            return new Uint8Array(obj.buffer)

        return temp
    }

    /**
     * Takes arbitrary buffer and returns integer.
     * @param  {ArrayBuffer} buffer
     * @return {Integer}
     */
    let arrayBufferToInt = (buffer) => {
        buffer = convertToUint8Array(buffer).buffer;

        if(buffer.byteLength === 1)
            return new Int8Array(buffer)[0];
        else if(buffer.byteLength === 2)
            return new Int16Array(buffer)[0];
        else
            return new Int32Array(buffer)[0];
    }

    /**
     * Takes any number of ArrayBuffers and returns merged ArrayBuffer
     * @param * {ArrayBuffer}
     * @return {ArrayBuffer}
     */
    let mergeArrayBuffers = function() {
        let args = Array.prototype.slice.call(arguments);
        if(args.length < 2)
            throw new Error('Minimum number of arguments is two!');

        return mergeArrayBuffersRecursively(args[0], args.slice(1))
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
    let mergeArrayBuffersRecursively = (buffer1, buffer2) => {

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
     * Takes arbitrary array buffer, and returns hex encoded string
     * @param  {ArrayBuffer} buffer - buffer
     * @return {String}             - hex encoded string
     */
    let arrayBufferToHex = (buffer) => {
        return Array.prototype.map
            .call(convertToUint8Array(buffer), x => ('00' + x.toString(16)).slice(-2))
            .join('');
    }

/* ----- UTILS ENDS ----- */


    /**
     * Returns byte size corresponding UINT
     * @type {Object}
     */
    let ByteSizeToUint = {
        1 : Uint8Array,
        2 : Uint16Array,
        4 : Uint32Array
    }

    class TLVGenerator {
        constructor (params) {
            this.TagFieldSize    = params.TagFieldSize;
            this.LengthFieldSize = params.LengthFieldSize;
            this.TagToString     = params.TagDirectory;
            this.StringToTag     = inverseDictionary(params.TagDirectory);

            this.TagFieldUINT    = ByteSizeToUint[this.TagFieldSize];
            this.LengthFieldUINT = ByteSizeToUint[this.LengthFieldSize];
        }

        /**
         * Returns object model of the given TLV schema
         * @param  {Object} - TLV Schema
         * @return {Object} - Object
         */
        getRequiredFields(schema) {
            let fields = {};

            if(schema.type === 'TLV')
                for(let key in schema.fields)
                    fields[key] = this.getRequiredFields(schema.fields[key]);
            else
                return schema.type

            return fields
        }

        /**
         * Generates TLV using given TLV schema and TLV object model structure
         * @param  {Object} - TLV Schema
         * @param  {Object} - TLV Schema object model
         * @return {ArrayBuffer} - TLV arrayBuffer
         */
        generateWithSchema(schema, object) {
            let buffer = new Uint8Array();

            if(schema.type === 'TLV') {
                for(let key of schema.order) {
                    let resultBuffer = this.generateRecursively(schema.fields[key], object[key], key);
                    buffer = mergeArrayBuffers(buffer, resultBuffer);
                }
            } else
                buffer = object;

            return buffer
        }


        /**
         * Generates TLV using given TLV schema and TLV object model structure
         * @param  {Object} - TLV Schema
         * @param  {Object} - TLV Schema object model
         * @return {ArrayBuffer} - TLV arrayBuffer
         */
        generateWithSchemaIgnoreMissing(schema, object) {
            let buffer = new Uint8Array();

            if(schema.type === 'TLV') {
                for(let key of schema.order) {
                    let resultBuffer = this.generateRecursively(schema.fields[key], object[key], key, true);
                    buffer = mergeArrayBuffers(buffer, resultBuffer);
                }
            } else
                buffer = object;

            return buffer
        }

        generateRecursively(schema, object, tagName, ignoreMissing) {

            /* If required field is missing */
            if(!object && (!schema || (schema && !schema.optional) && tagName) && !ignoreMissing)
                throw new Error(`${tagName} field is missing!`)

            /* if Object is an array buffer */
            if(schema.type === 'TLV' && object && type(object.byteLength) === 'Number') {
                let tag    = new this.TagFieldUINT([this.StringToTag[tagName]]);
                let length = new this.LengthFieldUINT([object.byteLength]);

                return mergeArrayBuffers(tag, length, object)
            }

            /* If parameter is optional */
            if(schema.optional && !object)
                return new Uint8Array();


            if(schema.type === 'TLV') {
                let tlvRepeatingTags;

                if(type(object) === 'Array')
                    tlvRepeatingTags = object;
                else
                    tlvRepeatingTags = [object];

                let finalBuffer = new Uint8Array();
                for(let tlvRepeatingTagObject of tlvRepeatingTags) {
                    let tempBuffer = new Uint8Array();
                    for(let key of schema.order) {
                        let resultBuffer = this.generateRecursively(schema.fields[key], tlvRepeatingTagObject[key], key);
                        tempBuffer = mergeArrayBuffers(tempBuffer, resultBuffer);
                    }

                    let tag    = new this.TagFieldUINT([this.StringToTag[tagName]]);
                    let length = new this.LengthFieldUINT([tempBuffer.byteLength]);

                    let buffer  = mergeArrayBuffers(tag, length, tempBuffer);
                    finalBuffer = mergeArrayBuffers(finalBuffer, buffer);
                }
                
                return finalBuffer
            } else
                return object
        }
    }

    class TLVParser {
        constructor (params) {
            this.TagFieldSize             = params.TagFieldSize;
            this.LengthFieldSize          = params.LengthFieldSize;
            this.TagToString              = params.TagDirectory;
            this.StringToTag              = inverseDictionary(params.TagDirectory);
            this.CustomTagParser          = params.CustomTagParser;
            this.CustomStructLengthParser = params.CustomStructLengthParser;
            this.CustomLengthFieldLengthParser = params.CustomLengthFieldLengthParser
        }

        /**
         * Checks of the buffer and length are of a correct size
         * @param  {Number} len          - length of the field
         * @param  {ArrayBuffer} buffer  - value buffer
         * @return {Boolean}             - if it is a valid arrayBuffer/number combo
         */
        badLength(len, buffer) {
            if(type(len) !== 'Number')
                return true

            if(len < 0)
                return true

            if(len > buffer.byteLength)
                return true

            return false
        }

        /**
         * Performs search of a TLV structure defined by TAG
         * @param  {ArrayBuffer} buffer - TLV Buffer
         * @param  {String}      TAG    - UAF TAG
         * @return {ArrayBuffer}        - Found structure
         */
        searchTAG(buffer, TAG) {
            let finalBuffer = this.searchTAGRecursive(buffer, TAG);

            return finalBuffer;
        }

        searchTAGRecursive(buffer, TAG) {
            let TSize  = this.TagFieldSize;
            let LSize  = this.LengthFieldSize;
            let TLSize = this.TagFieldSize + this.LengthFieldSize;

            if(!this.TagToString[arrayBufferToInt(buffer.slice(0, TSize))] || buffer.byteLength < TLSize)
                return new Uint8Array()

            while(buffer.byteLength > 0) {
                let tag        = arrayBufferToInt(buffer.slice(0, TSize));
                let tag_string = this.TagToString[tag];
                let len        = arrayBufferToInt(buffer.slice(TSize, TLSize));
                let newBuffer  = buffer.slice(TLSize, TLSize + len)

                if(tag_string === TAG)
                    return buffer.slice(0, TLSize + len);

                let finalBuffer = this.searchTAGRecursive(newBuffer, TAG);

                if(finalBuffer.byteLength)
                    return finalBuffer;

                buffer = buffer.slice(TLSize + len, buffer.byteLength);
            }

            return new Uint8Array()
        }

        /**
         * Takes arbitrary ArrayBuffer encoded TLV and returns JSON object
         * @param  {ArrayBuffer} buffer            - ArrayBuffer encoded TLV structure
         * @return {Object}
         */
        parse(buffer) {
            return this.parseRecursive(buffer, undefined);
        }

        /**
         * Takes arbitrary ArrayBuffer encoded TLV and returns JSON object with result value fields in raw ArrayBuffer
         * @param  {ArrayBuffer} buffer            - ArrayBuffer encoded TLV structure
         * @return {Object}
         */
        parseButSkipValueDecoding(buffer) {
            return this.parseRecursive(buffer, undefined, true);
        }

        /**
         * Default Structure length parser
         * @param  {ArrayBuffer} buffer - TLV buffer
         * @return {Number}             - the length of the VALUE
         */
        defaultStructLengthParser(buffer) {
            if(this.CustomStructLengthParser)
                return this.CustomStructLengthParser(buffer)

            let TSize         = this.TagFieldSize;
            let TagLengthSize = this.TagFieldSize + this.LengthFieldSize;

            return arrayBufferToInt(buffer.slice(TSize, TagLengthSize))
        }

        /**
         * Default length of the LENGTH field parser. Calculates the length of the LENGTH field.
         * @param  {ArrayBuffer} buffer - TLV buffer
         * @return {Number}             - the length of the VALUE
         */
        defaultLengthFieldLengthParser(buffer) {
            if(this.CustomLengthFieldLengthParser)
                return this.CustomLengthFieldLengthParser(buffer)

            return this.LengthFieldSize
        }

        /**
         * Takes ArrayBuffer encoded TLV and returns an object
         * @param  {ArrayBuffer} buffer            - ArrayBuffer encoded TLV
         * @param  {String}      parentTag         - Parent tag
         * @param  {Boolean}     skipValueDecoding - Forces parser to skip value decoding, and instead return array buffer
         * @return {Object}
         */
        parseRecursive(buffer, parentTag, skipValueDecoding) {

            let TSize  = this.TagFieldSize;
            let LSize  = this.defaultLengthFieldLengthParser(buffer);
            let MinTLSize = TSize + LSize;

            let tlv = {};

            if(!this.TagToString[arrayBufferToInt(buffer.slice(0, TSize))] || buffer.byteLength < MinTLSize) {
                return this.parseTAGValues(buffer, parentTag, skipValueDecoding)
            }

            while(buffer.byteLength > 0) {
                let tag        = arrayBufferToInt(buffer.slice(0, TSize));
                let tag_string = this.TagToString[tag];

                let len        = this.defaultStructLengthParser(buffer);
                let newBuffer  = buffer.slice(MinTLSize, MinTLSize + len);

                if(this.badLength(len, newBuffer))
                    return this.parseTAGValues(buffer, parentTag, skipValueDecoding)

                if(!tag_string)
                    tag_string = tag.toString();

                let value = this.parseRecursive(newBuffer, tag_string, skipValueDecoding);

                /* If there are repeat of same tag it becomes an array of values */
                if(!tlv[tag_string]) {
                    tlv[tag_string] = value;
                } else {
                    if(type(tlv[tag_string]) !== 'Array')
                        tlv[tag_string] = [tlv[tag_string]];

                    tlv[tag_string].push(value);
                }

                buffer = buffer.slice(len + MinTLSize, buffer.byteLength);
            }

            return tlv
        }

        /**
         * Takes arbitrary Base64URL encoded data, and tries to decode it
         * @param  {String}  values          - Base64URL encoded data
         * @param  {String}  parentTag       - Parent TAG value
         * @param  {Boolean} skipValueDecoding - Forces parser to skip TAG decoding, and return array buffer
         * @return {*}                       - Arbitrary object
         */
        parseTAGValues(buffer, parentTag, skipValueDecoding) {
            if(!skipValueDecoding) {
                if(this.CustomTagParser) 
                    return this.CustomTagParser(buffer, parentTag);
                else
                    return arrayBufferToHex(buffer);
            }

            return buffer
        }
    }


    /**
     * Verifies validity of a given tlvParams
     * @param  {Object}
     */
    let verifyTLVParams = (tlvParams) => {
        if(!tlvParams)
            throw new Error('tlvParams is undefined!');

        if(type(tlvParams) !== 'Object')
            throw new Error('tlvParams must be an Object!');

        if(!ByteSizeToUint[tlvParams.TagFieldSize])
            throw new RangeError(`Given TagFieldSize is invalid. Available field sizes ${Object.keys(ByteSizeToUint)}`);

        if(!ByteSizeToUint[tlvParams.LengthFieldSize])
            throw new RangeError(`Given LengthFieldSize is invalid. Available field sizes ${Object.keys(ByteSizeToUint)}`);

        if(!tlvParams.TagDirectory)
            throw new Error('TagDirectory field is missing!');

        if(type(tlvParams.TagDirectory) !== 'Object')
            throw new Error('TagDirectory must be an Object!');

        if(Object.keys(tlvParams.TagDirectory).some(isNaN))
            throw new Error('TagDirectory keys must be an integer value of a given TLV tag!');

        if(tlvParams.CustomTagParser && type(tlvParams.CustomTagParser) !== 'Function')
            throw new Error('CustomTagParser field must be a function!');
    }

    class TLV {
        constructor(params) {
            verifyTLVParams(params);

            params.TagDirectory = Object.assign({}, params.TagDirectory)

            this.generator      = new TLVGenerator(params);
            this.parser         = new TLVParser(params);
        }
    }

    /*
     * Exporting and stuff
     */
    if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
        module.exports = TLV;
    } else {
        if (typeof define === 'function' && define.amd) {
            define([], function() {
                return TLV;
            });
        } else {
            window.TLV = TLV;
        }
    }

})()