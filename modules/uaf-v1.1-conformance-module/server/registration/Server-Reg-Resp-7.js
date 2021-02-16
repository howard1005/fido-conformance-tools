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

        Server-Reg-Resp-7

        Test server processing of different authentication algorithms and public key formats

    `, function() {

    this.timeout(5000);
    this.retries(3);

/* ---------- Negative Tests ---------- */
    it(`P-1

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding, and send it to the server. Server must accept response.  

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

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding, and send it to the server. Server must accept response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })


    it(`P-3

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding, and send it to the server. Server must accept response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC02')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-4

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding, and send it to the server. Server must accept response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC04')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-5

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding, and send it to the server. Server must accept response.

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC09')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-6

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_RAW for public key encoding, and send it to the server. Server must accept response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0B')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-7

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding, and send it to the server. Server must accept response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0A')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-8

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER as signature algorithm, UAF_ALG_KEY_ECC_X962_DER for public key encoding, and send it to the server. Server must accept response.  

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC0C')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-9

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding, and send it to the server. Server must accept response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC05')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-10

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding, and send it to the server. Server must accept response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC07')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-11

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding, and send it to the server. Server must accept response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC06')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`P-12

        Get registration request, generate a valid registration response with FULL attestation that uses UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding, and send it to the server. Server must accept response.   

    `, () => {
        let username = generateRandomString();
        return rest.register.get(1200, username)
            .then((messages) => {
                let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC08')
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                return rest.register.post(success.uafProtocolMessage, 1200, username)
            })
    })

    it(`F-13

        Get registration request, generate a valid registration response with FULL attestation that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding, and send it to the server. Server must accept response.   

    `)

    it(`F-14

        Get registration request, generate a valid registration response with FULL attestation that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_RAW for public key encoding, and send it to the server. Server must accept response.   

    `)

    it(`F-15

        Get registration request, generate a valid registration response with FULL attestation that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding, and send it to the server. Server must accept response.   

    `)

    it(`F-16

        Get registration request, generate a valid registration response with FULL attestation that uses ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER as signature algorithm, UAF_ALG_KEY_RSA_2048_PSS_DER for public key encoding, and send it to the server. Server must accept response.   

    `)
})
