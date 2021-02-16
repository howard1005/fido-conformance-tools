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

        Server-Auth-Resp-7

        Test server processing of different authentication algorithms

    `, function() {

    let username = generateRandomString();
    let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
    before(() => {
        
        return rest.register.get(1200, username)
            .then((response) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(response)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((data) => rest.register.post(data.uafProtocolMessage, 1200, username))
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding, and send it to the server. Server must accept response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-2

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding, and send it to the server. Server must accept response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-3

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding, and send it to the server. Server must accept response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC02')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-4

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding, and send it to the server. Server must accept response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC04')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-5

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding, and send it to the server. Server must accept response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC09')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-6

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding, and send it to the server. Server must accept response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0B')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-7

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding, and send it to the server. Server must accept response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0A')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-8

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding, and send it to the server. Server must accept response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0C')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-9

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding, and send it to the server. Server must accept response. 

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC05')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-10

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding, and send it to the server. Server must accept response. 

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC07')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-11

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding, and send it to the server. Server must accept response. 

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC06')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-12

        Get authenticate request, generate a valid authenticate response that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding, and send it to the server. Server must accept response. 

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC08')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })
    
    it(`P-13

        Get authenticate request, generate a valid authenticate response that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding, and send it to the server. Server must accept response. 

    `)

    it(`P-14

        Get authenticate request, generate a valid authenticate response that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding, and send it to the server. Server must accept response. 

    `)

    it(`P-15

        Get authenticate request, generate a valid authenticate response that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding, and send it to the server. Server must accept response. 

    `)

    it(`P-16

        Get authenticate request, generate a valid authenticate response that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding, and send it to the server. Server must accept response. 

    `)

/* ---------- Negative Tests ---------- */

    let tlv = new TLV({
        'TagFieldSize' : 2,
        'LengthFieldSize' : 2,
        'TagDirectory': TAG_DIR,
        'CustomTagParser': window.UAF.helpers.CustomTagParser
    })

    it(`F-1

        Get authenticate request, generate an authenticate response that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding. Invalidate the signature(by randomly modifying it), and send it to the server. Server must reject response. 

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-2

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })


    it(`F-3

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC02')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-4

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC04')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-5

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC09')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-6

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0B')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-7

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0A')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-8

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response.    

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0C')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-9

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response. HA256_RAW and signature invalidated (e.g. by adding 0x03 to byte number 15 in TAG_SIGNATURE).

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC05')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-10

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response. 

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC07')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-11

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response. 

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC06')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })


    it(`F-12

        Get authenticate request, generate an authentication response that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response. 

    `, () => {

        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC08')
        return rest.register.get(1200, username)
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];
                let assertion = message.assertions[0].assertion;
                let assertionBuffer = base64url.decode(assertion);
                let AUTHR_STRUCT = tlv.parser.parseButSkipValueDecoding(assertionBuffer)

                let signatureBuffer = new Uint8Array(AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE);
                signatureBuffer[3] = signatureBuffer[3] + 42;

                AUTHR_STRUCT.TAG_UAFV1_AUTH_ASSERTION.TAG_SIGNATURE = signatureBuffer;

                assertionBuffer = tlv.generator.generateWithSchema(UAF.TLVSchemas.SIGN_ASSERTION_SCHEMA, AUTHR_STRUCT)
                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-13

        Get authenticate request, generate an authentication response that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response. 

    `)

    it(`F-14

        Get authenticate request, generate an authentication response that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response. 

    `)

    it(`F-15

        Get authenticate request, generate an authentication response that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response. 

    `)

    it(`F-16

        Get authenticate request, generate an authentication response that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding. Invalidate the signature(by randomly modifying it) and send it to the server. Server must reject response. 

    `)
})
