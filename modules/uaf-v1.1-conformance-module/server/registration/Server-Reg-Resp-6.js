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

describe(`

        Server-Reg-Resp-6

        Test server processing of the registration response message assertion TLV

    `, function() {

    this.timeout(5000);
    this.retries(3);

    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    })

/* ---------- Positive Tests ---------- */

    it(`P-1

        Get registration request, generate registration response with a valid assertion TLV with FULL attestation, and send it to the server. Server must accept response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-2

        Get registration request, generate registration response with a valid assertion TLV with SURROGATE attestation, and send it to the server. Server must accept response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0D')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

/* ---------- Negative Tests ---------- */
    it(`F-1

        Get registration request, generate registration response with assertion TLV missing TAG_UAFV1_REG_ASSERTION, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
        let registrationPair = undefined;

        return rest.register.get(1200, username)
            .then((data) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(data)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let message              = tryDecodeJSON(data.uafProtocolMessage)[0];
                let assertionUINT8Buffer = new Uint8Array();
              
                message.assertions[0].assertion = base64url.encode(assertionUINT8Buffer);
                let uafResponse = JSON.stringify([message]);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-2

        Get registration request, generate registration response with assertion TLV.TAG_UAFV1_REG_ASSERTION missing TAG_UAFV1_KRD, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
        let registrationPair = undefined;

        return rest.register.get(1200, username)
            .then((data) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(data)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let message              = tryDecodeJSON(data.uafProtocolMessage)[0];
                let assertionUINT8Buffer = new Uint8Array(base64url.decode(message.assertions[0].assertion));
                assertionUINT8Buffer[5]  = 4; // Changing to TAG_UAFV1_SIGNED_DATA
              
                message.assertions[0].assertion = base64url.encode(assertionUINT8Buffer);
                let uafResponse = JSON.stringify([message]);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-3

        Get registration request, generate registration response with assertion TLV with leftover bytes(TAG_UAFV1_REG_ASSERTION length is 2046, and TLV length is 2048 bytes. 2 bytes leftover), and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
        let registrationPair = undefined;

        return rest.register.get(1200, username)
            .then((data) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(data)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let message   = tryDecodeJSON(data.uafProtocolMessage)[0];
                let assertionBuffer = base64url.decode(message.assertions[0].assertion);

                assertionBuffer = mergeArrayBuffers(assertionBuffer, new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
              
                message.assertions[0].assertion = base64url.encode(assertionBuffer);
                let uafResponse = JSON.stringify([message]);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-4

        Get registration request, generate registration response with assertion TLV with TAG_UAFV1_AUTH_ASSERTION instead of TAG_UAFV1_REG_ASSERTION, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01');
        let registrationPair = undefined;

        return rest.register.get(1200, username)
            .then((data) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(data)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => {
                let message              = tryDecodeJSON(data.uafProtocolMessage)[0];
                let assertionUINT8Buffer = new Uint8Array(base64url.decode(message.assertions[0].assertion));
                assertionUINT8Buffer[0]  = 2; // Changing to TAG_UAFV1_AUTH_ASSERTION
              
                message.assertions[0].assertion = base64url.encode(assertionUINT8Buffer);
                let uafResponse = JSON.stringify([message]);

                return rest.register.post(uafResponse, 1498, username)
            })
    })

    it(`F-5

        Get registration request, generate registration response with assertion TAG_UAFV1_KRD missing TAG_AAID, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'skipAAID': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-6

        Get registration request, generate registration response with assertion TAG_AAID length is 0(zero), and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'emptyAAID': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-7

        Get registration request, generate registration response with assertion TAG_AAID does NOT contain expected AAID, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'customAAID': 'FFFF#FFFF'
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-8

        Get registration request, generate registration response with assertion TAG_UAFV1_KRD missing TAG_ASSERTION_INFO, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'skipAssertionInfo': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-9

        Get registration request, generate registration response with assertion TAG_ASSERTION_INFO.length is bigger than 7 bytes, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'longAssertionInfo': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-10

        Get registration request, generate registration response with assertion TAG_ASSERTION_INFO.length is less than 7 bytes, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'shortAssertionInfo': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-11

        Get registration request, generate registration response with assertion TAG_ASSERTION_INFO length is 0(zero), and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'emptyAssertionInfo': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-12

        Get registration request, generate registration response with assertion TAG_ASSERTION_INFO.AuthenticationMode is NOT set to 0x01(indicating that the user has NOT explicitly verified the action), and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'authenticationModeNotExplicitlyVefied': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-13

        Get registration request, generate registration response with assertion TAG_ASSERTION_INFO.SignatureAlgAndEncoding is NOT set to the used signature algorithm, send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'badSignatureAlgorithm': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-14

        Get registration request, generate registration response with assertion TAG_ASSERTION_INFO.PublicKeyAlgAndEncoding is NOT set to the used public key encoding algorithm, send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'badPublicKeyAlgorithm': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-15

        Get registration request, generate registration response with assertion TAG_UAFV1_KRD missing TAG_FINAL_CHALLENGE_HASH, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'skipFinalChallenge': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-16

        Get registration request, generate registration response with assertion TAG_FINAL_CHALLENGE_HASH containing invalid hash, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'FCHash': stringToArrayBuffer('ThisIsNotAHashYouAreLookingFor!')
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-17

        Get registration request, generate registration response with assertion TAG_FINAL_CHALLENGE_HASH containing hash that is been generate with a hash function that is NOT specified by authenticationAlgorithm, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'FCHashFunction': 'SHA-1'
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-18

        Get registration request, generate registration response with assertion TAG_UAFV1_KRD missing TAG_KEYID, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'skipKeyID': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-19

        Get registration request, generate registration response with assertion TAG_KEYID length is 0(zero), and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'emptyKeyID': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-20

        Get registration request, generate registration response with assertion TAG_KEYID length is less than 32 bytes, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'shortKeyID': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-21

        Get registration request, generate registration response with assertion TAG_KEYID length is more than 32 bytes, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'longKeyID': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-22

        Get registration request, generate registration response with assertion TAG_UAFV1_KRD missing TAG_COUNTERS, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'skipCounters': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-23

        Get registration request, generate registration response with assertion TAG_COUNTERS is NOT eight(8) bytes long, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'badCounters': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-24

        Get registration request, generate registration response with assertion TAG_UAFV1_KRD missing TAG_PUB_KEY, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'skipPublicKey': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-25

        Get registration request, generate registration response with assertion TAG_PUB_KEY length is 0(zero), and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'emptyPublicKey': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

/* ----- FULL ----- */
    it(`F-26

        For FULL attestation: Get registration request, generate registration response with assertion TAG_UAFV1_REG_ASSERTION missing TAG_ATTESTATION_BASIC_FULL, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'skipAttestation': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-27

        For FULL attestation: Get registration request, generate registration response with assertion TAG_ATTESTATION_BASIC_FULL missing TAG_SIGNATURE, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'skipSignature': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-28

        For FULL attestation: Get registration request, generate registration response with assertion TAG_SIGNATURE length is 0(zero), and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'emptySignature': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-29

        For FULL attestation: Get registration request, generate registration response with assertion TAG_SIGNATURE is NOT a valid signature, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'badSignature': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-30

        For FULL attestation: Get registration request, generate registration response with assertion TAG_ATTESTATION_BASIC_FULL missing TAG_ATTESTATION_CERT, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'skipCert': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-31

        For FULL attestation: Get registration request, generate registration response with assertion TAG_ATTESTATION_CERT length is 0(zero), and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'emptyCert': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-32

        For FULL attestation: Get registration request, generate registration response with assertion TAG_ATTESTATION_CERT is NOT a valid PKIX X509 Certificate, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
                    'context': 'Reg',
                    'badCert': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

/* ----- SURROGATE ----- */
    it(`F-33

        For SURROGATE attestation: Get registration request, generate registration response with assertion TAG_UAFV1_REG_ASSERTION missing TAG_ATTESTATION_BASIC_SURROGATE, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0D', {
                    'context': 'Reg',
                    'skipAttestation': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-34

        For SURROGATE attestation: Get registration request, generate registration response with assertion TAG_ATTESTATION_BASIC_SURROGATE missing TAG_SIGNATURE, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0D', {
                    'context': 'Reg',
                    'skipSignature': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-35

        For SURROGATE attestation: Get registration request, generate registration response with assertion TAG_SIGNATURE length is 0(zero), and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0D', {
                    'context': 'Reg',
                    'emptySignature': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })

    it(`F-36

        For SURROGATE attestation: Get registration request, generate registration response with assertion TAG_SIGNATURE is NOT a valid signature, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {     
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0D', {
                    'context': 'Reg',
                    'badSignature': true
                })

                let UAFMessage = {  
                    'uafProtocolMessage': JSON.stringify(messages)
                }     

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1498, username))     
    })
})
