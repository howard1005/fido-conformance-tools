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

        Server-Auth-Resp-6

        Test server processing of the registration response message assertion TLV

    `, function() {

    this.timeout(5000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Get authentication request, generate authentication response with a valid assertion TLV, and send it to the server. Server must accept response.    

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })

    it(`P-2

        Get authentication request, with transaction conformation request of type "text/plain", generate authentication response with a valid assertion TLV, and send it to the server. Server must accept response.     

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01')

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Send 200$ to Scrooge McDuck?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-3

        Get authentication request, with transaction conformation request of type "image/png", generate authentication response with a valid assertion TLV, and send it to the server. Server must accept response.

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC02');

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Send 200$ to Scrooge McDuck?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })

    it(`P-4

        Get authentication request, for authentication with prividged software display(tcDisplay=0x0003), with transaction conformation request of type "text/plain", generate authentication response with a valid assertion TLV, and send it to the server. Server must accept response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03')

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Send 200$ to Scrooge McDuck?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1200, username))
    })


/* ---------- Negative Tests ---------- */
    it(`F-1

        Get authentication request, generate authentication response with assertion TLV missing TAG_UAFV1_AUTH_ASSERTION, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03')

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];

                let assertionBuffer = new Uint8Array(base64url.decode(message.assertions[0].assertion));
                assertionBuffer[0]  = 1; // Changing to TAG_UAFV1_REG_ASSERTION

                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-2

        Get authentication request, generate authentication response with assertion TAG_UAFV1_AUTH_ASSERTION missing TAG_UAFV1_SIGNED_DATA, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03')

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];

                let assertionBuffer = new Uint8Array(base64url.decode(message.assertions[0].assertion));
                assertionBuffer[5]  = 3; // Changing to KRD

                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-3

        Get authentication request, generate authentication response with assertion TLV with leftover bytes(TLV.TAG_UAFV1_AUTH_ASSERTION length is 2046, and TLV length is 2048 bytes. 2 bytes leftover), and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03')

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];

                let assertionBuffer = new Uint8Array(base64url.decode(message.assertions[0].assertion));
                assertionBuffer = mergeArrayBuffers(assertionBuffer, new Uint32Array([0xdeadbeef]));

                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-4

        Get authentication request, generate authentication response with assertion TLV with TAG_UAFV1_REG_ASSERTION instead of TAG_UAFV1_AUTH_ASSERTION, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03')

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => {
                let message = tryDecodeJSON(success.uafProtocolMessage)[0];

                let assertionBuffer = new Uint8Array(base64url.decode(message.assertions[0].assertion));
                assertionBuffer = mergeArrayBuffers(assertionBuffer, new Uint32Array([0xdeadbeef]));

                message.assertions[0].assertion = base64url.encode(assertionBuffer);

                let uafResponse = JSON.stringify([message]);

                return rest.authenticate.post(uafResponse, 1498, username)
            })
    })

    it(`F-5

        Get authentication request, generate authentication response with assertion TAG_UAFV1_SIGNED_DATA missing TAG_AAID, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr    = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'skipAAID': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-6

        Get authentication request, generate authentication response with assertion TAG_AAID length is 0(zero), and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'emptyAAID': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-7

        Get authentication request, generate authentication response with assertion TAG_AAID does NOT contain expected AAID, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'customAAID': 'FFFF#FFFF'
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-8

        Get authentication request, generate authentication response with assertion TAG_UAFV1_SIGNED_DATA missing TAG_ASSERTION_INFO, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'skipAssertionInfo': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-9

        Get authentication request, generate authentication response with assertion TAG_ASSERTION_INFO.length is bigger than 5 bytes, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'longAssertionInfo': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-10

        Get authentication request, generate authentication response with assertion TAG_ASSERTION_INFO.length is less than 5 bytes, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'shortAssertionInfo': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-11

        Get authentication request, generate authentication response with assertion TAG_ASSERTION_INFO length is zero(0), and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'emptyAssertionInfo': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-12

        Get authentication request, generate authentication response with assertion TAG_ASSERTION_INFO.AuthenticationMode is set to 0x02(indicating that user had been presented with transaction conformation), and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'TCAuthenticationMode': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-13

        Get authentication request, generate authentication response with assertion TAG_ASSERTION_INFO.AuthenticationMode is set to 0x00(indicating that user has NOT explicitly consent operation), and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'badAuthenticationMode': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-14

        Get authentication request, with transaction conformation request, generate authentication response with assertion TAG_ASSERTION_INFO.AuthenticationMode is set to 0x01(indicating that user had explicitly verified auth request), and send it to the server. Server MUST reject response.

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'badTCAuthenticationMode': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Elizabeth II, Dei Gratia Britanniarum Regnorumque Suorum Ceterorum Regina, Consortionis Populorum Princeps, Fidei Defensor?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-15

        Get authentication request, generate authentication response with assertion TAG_ASSERTION_INFO.SignatureAlgAndEncoding is NOT set to the used signature algorithm, send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'badSignatureAlgorithm': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-16

        Get authentication request, generate authentication response with assertion TAG_UAFV1_SIGNED_DATA missing TAG_AUTHENTICATOR_NONCE, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'skipAuthrNonce': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-17

        Get authentication request, generate authentication response with assertion TAG_AUTHENTICATOR_NONCE length is 0(zero), and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'emptyAuthrNonce': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-18

        Get authentication request, generate authentication response with assertion TAG_AUTHENTICATOR_NONCE length is less than 8(eight) bytes, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'shortAuthrNonce': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-19

        Get authentication request, generate authentication response with assertion TAG_UAFV1_SIGNED_DATA missing TAG_FINAL_CHALLENGE_HASH, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'skipFinalChallenge': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-20

        Get authentication request, generate authentication response with assertion TAG_FINAL_CHALLENGE_HASH length is 0(zero), and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'emptyFinalChallenge': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-21

        Get authentication request, generate authentication response with assertion TAG_FINAL_CHALLENGE_HASH containing invalid hash, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'FCHash': new Uint32Array([0xdeadbeef])
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-22

        Get authentication request, generate authentication response with assertion TAG_FINAL_CHALLENGE_HASH containing hash that is been generate with a hash function that is NOT specified by authenticationAlgorithm, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'FCHashFunction': 'SHA-1'
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-23

        For authenticator that has does not use privileged software(tcDisplay != 0x0003): Get authentication request, generate authentication response with assertion TAG_UAFV1_SIGNED_DATA missing TAG_TRANSACTION_CONTENT_HASH, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'skipTransactionContent': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-24

        For authenticator that has does not use privileged software(tcDisplay != 0x0003): Get authentication request, generate authentication response with assertion TAG_TRANSACTION_CONTENT_HASH length is NOT 0(zero), and send it to the server. Server must reject response.    
    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'TCHash': new Uint8Array([0xde, 0xad, 0xbe, 0xef])
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-25

        For authenticator that has does not use privileged software(tcDisplay != 0x0003): Get authentication request, with transaction conformation request, generate authentication response with assertion TAG_TRANSACTION_CONTENT_HASH length is 0(zero), and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'emptyTransactionContent': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-26

        For authenticator that has does not use privileged software(tcDisplay != 0x0003): Get authentication request, with transaction conformation request, generate authentication response with assertion TAG_TRANSACTION_CONTENT_HASH containing invalid hash of the transaction conformation, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'TCHash': new Uint8Array([0xde, 0xad, 0xbe, 0xef])
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-27

        For authenticator that USES privileged software(tcDisplay == 0x0003): Get authentication request, generate authentication response with assertion TAG_UAFV1_SIGNED_DATA missing TAG_TRANSACTION_CONTENT_HASH, and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03', {
            'context': 'Auth',
            'skipTransactionContent': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-28

        For authenticator that USES privileged software(tcDisplay == 0x0003): Get authentication request, generate authentication response with assertion TAG_TRANSACTION_CONTENT_HASH length is NOT 0(zero), and send it to the server. Server must reject response.   

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03', {
            'context': 'Auth',
            'TCHash': new Uint8Array([0xde, 0xad, 0xbe, 0xef])
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-29

        For authenticator that USES privileged software(tcDisplay == 0x0003): Get authentication request, with transaction conformation request, generate authentication response with assertion TAG_TRANSACTION_CONTENT_HASH length is 0(zero), and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03', {
            'context': 'Auth',
            'emptyTransactionContent': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-30

        For authenticator that USES privileged software(tcDisplay == 0x0003): Get authentication request, with transaction conformation request, generate authentication response with assertion TAG_TRANSACTION_CONTENT_HASH containing invalid hash of the transaction conformation, and send it to the server. Server must reject response.  

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC03', {
            'context': 'Auth',
            'TCHash': new Uint8Array([0xde, 0xad, 0xbe, 0xef])
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-31

        Get authentication request, generate authentication response with assertion TAG_UAFV1_SIGNED_DATA missing TAG_KEYID, and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'skipKeyID': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-32

        Get authentication request, generate authentication response with assertion TAG_KEYID length is 0(zero), and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'emptyKeyID': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-33

        Get authentication request, generate authentication response with assertion TAG_KEYID length is less than 32 bytes, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'shortKeyID': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-34

        Get authentication request, generate authentication response with assertion TAG_KEYID length is more than 32 bytes, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'longKeyID': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-35

        Get authentication request, generate authentication response with assertion TAG_UAFV1_SIGNED_DATA missing TAG_COUNTERS, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'skipCounters': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-36

        Get authentication request, generate authentication response with assertion TAG_COUNTERS is NOT four(4) bytes long, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'badSignatureCounter': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-37

        Get authentication request, generate authentication response with assertion TAG_UAFV1_AUTH_ASSERTION missing TAG_SIGNATURE, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'skipSignature': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-38

        Get authentication request, generate authentication response with assertion TAG_SIGNATURE length is 0(zero), and send it to the server. Server must reject response.    

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'emptySignature': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })

    it(`F-39

        Get authentication request, generate authentication response with assertion TAG_SIGNATURE is NOT a valid signature, and send it to the server. Server must reject response. 

    `, () => {
        let username = generateRandomString();
        let authr = getNewAuthenticator(window.config.test.serverURL, 'FFFF#FC01', {
            'context': 'Auth',
            'badSignature': true
        })

        return rest.register.get(1200, username)
            .then((messages) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(messages)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success)  => rest.register.post(success.uafProtocolMessage, 1200, username))
            .then(() => rest.authenticate.get(1200, username, 'Transfer 200$ to Montgomery Burns?'))
            .then((success) => {
                let UAFMessage = {
                    'uafProtocolMessage': JSON.stringify(success)
                }

                return authr.processUAFOperation(UAFMessage)
            })
            .then((success) => rest.authenticate.post(success.uafProtocolMessage, 1498, username))
    })
})
