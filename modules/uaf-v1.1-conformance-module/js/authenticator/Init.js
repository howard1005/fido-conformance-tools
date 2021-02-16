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
    window.UAF = {};

    window.UAF.helpers = {
        /**
         * TagParsingHelper
         * @param  {ArrayBuffer} buffer    - buffer to decode
         * @param  {String}      parentTag - string value of parent TAG
         * @return {*}
         */
        'CustomTagParser': (buffer, parentTag) => {
            let typeTable = {
                'TAG_APPID': 'String',
                'TAG_AUTHENTICATOR_INDEX': 'Integer',
                'TAG_ATTESTATION_TYPE': 'TAG',
                'TAG_USERNAME': 'String',
                'TAG_AAID': 'String'
            }

            switch(parentTag) {
                case 'TAG_ASSERTION_INFO':
                    
                    return {
                        'AuthenticatorVersion'    : arrayBufferToInt(buffer.slice(0,2)),
                        'AuthenticationMode'      : arrayBufferToInt(buffer.slice(2,3)),
                        'SignatureAlgAndEncoding' : ALG_DIR[arrayBufferToInt(buffer.slice(3,5))],
                        'PublicKeyAlgAndEncoding' : ALG_DIR[arrayBufferToInt(buffer.slice(5,7))]
                    }

                    break;

                case 'TAG_COUNTERS':
                    return {
                        'SignCounter' : arrayBufferToInt(buffer.slice(0,4)),
                        'RegCounter'  : arrayBufferToInt(buffer.slice(4,8))
                    }

                    break;

                case 'TAG_STATUS_CODE':
                    let code = arrayBufferToInt(buffer);
                    return CMD_STATUS_CODES[code]
                    break;

                default:
                    let fieldType = typeTable[parentTag];
                    switch(fieldType) {
                        case 'String':
                            return arrayBufferToString(buffer);
                            break
                        case 'TAG':
                            return TAG_DIR[arrayBufferToInt(buffer)];
                            break;
                        case 'Integer':
                            return arrayBufferToInt(buffer);
                            break
                        default:
                            return base64url.encode(buffer);
                            break
                    }
                    
            }
        }
    }
})()