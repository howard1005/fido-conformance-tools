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

        Protocol-Auth-Req-7

        Test the Transaction SEQUENCE

    `, function() {
        
    this.timeout(30000);
    this.retries(3);

    after(() => {
       return getTestStaticJSON(`Protocol-Dereg-Req-P`)
        .then((data) => {
            data[0].authenticators = [{'aaid': '', 'keyID': ''}]
            
            let uafmessage = {'uafProtocolMessage' : JSON.stringify(data)}

            return expectProcessUAFOperationSucceed(uafmessage);
        })
    })
    

    before(function() {
        this.timeout(30000);
        return getTestStaticJSON('Protocol-Reg-Req-P')
            .then((response) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(response),
                }

                return authenticator.processUAFOperation(uafmessage)
            })
            .catch((error) => {
                throw new Error('The before-hook has thrown an error. Please check that you are passing positive tests in request test cases, as it is the most likely cause of hook\'s failure!\n\n The error message is: ' + error);
            })
    })


/* ---------- Positive Tests ---------- */

    it(`P-1

       If Authenticator supports "text/plain" for Transaction confirmation: Send a valid AuthenticationRequest containing valid "text/plain" Transaction, wait for the response, and check that API does NOT return an error    

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 
        && config.test.metadataStatement.tcDisplayContentType === 'text/plain') {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {

                    data[0].transaction = [
                        {
                            'contentType': 'text/plain',
                            'content': stringToBase64URL('THIS IS TEST AND ITS COMPLETELY NOT FUNNY, SO PLEASE ACCEPT THE TRANSACTION!')
                        }
                    ]

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationSucceed(uafmessage);
                })
        }
    })

    it(`P-2

        If Authenticator supports "image/png" for Transaction confirmation: Send a valid AuthenticationRequest containing valid "image/png" Transaction, wait for the response, and check that API does NOT return an error

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 
        && config.test.metadataStatement.tcDisplayContentType === 'image/png') {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {

                    data[0].transaction = [
                        {
                            'contentType': 'image/png',
                            'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                            'tcDisplayPNGCharacteristics': config.test.metadataStatement.tcDisplayPNGCharacteristics[0]
                        }
                    ]

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationSucceed(uafmessage);
                })
        }
    })

/* ---------- Negative Tests ---------- */
    describe(`F-1

        If Authenticator supports Transaction confirmation: Send three AuthenticationRequests containing Transaction, with "contentType" field set to "null", "undefined" and "empty" DOMString, wait for the responses, and check that API returns a PROTOCOL_ERROR(0x06) error for each of the response   

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 ) {
            it('contentType is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': null,
                                'content': stringToBase64URL('THIS IS TEST AND ITS COMPLETELY NOT FUNNY, SO PLEASE ACCEPT THE TRANSACTION!')
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('contentType is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': undefined,
                                'content': stringToBase64URL('THIS IS TEST AND ITS COMPLETELY NOT FUNNY, SO PLEASE ACCEPT THE TRANSACTION!')
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('contentType is empty DOMString', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': '',
                                'content': stringToBase64URL('THIS IS TEST AND ITS COMPLETELY NOT FUNNY, SO PLEASE ACCEPT THE TRANSACTION!')
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        }
    })

    it(`F-2

        If Authenticator supports Transaction confirmation: Send AuthenticationRequest containing Transaction with "contentType" field is NOT of type DOMString, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error 

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 ) {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {

                    data[0].transaction = [
                        {
                            'contentType': 0xdeadbeef,
                            'content': stringToBase64URL('THIS IS TEST AND ITS COMPLETELY NOT FUNNY, SO PLEASE ACCEPT THE TRANSACTION!')
                        }
                    ]

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        }
    })

    it(`F-3

        If Authenticator supports Transaction confirmation: Send AuthenticationRequest containing Transaction with "content" field is NOT of type DOMString, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error 

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 ) {
            if(config.test.metadataStatement.tcDisplayContentType === 'text/plain') {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'text/plain',
                                'content': 0xdeadbeef
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            } else if(config.test.metadataStatement.tcDisplayContentType === 'image/png') {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 0xdeadbeef,
                                'tcDisplayPNGCharacteristics': config.test.metadataStatement.tcDisplayPNGCharacteristics[0]
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            }
        }
    })

    describe(`F-4

        If Authenticator supports "text/plain" for Transaction confirmation: Send three AuthenticationRequests containing "text/plain" Transaction, with "content" field set to "null", "undefined" and "empty" DOMString, wait for the responses, and check that API returns a PROTOCOL_ERROR(0x06) error for each of the response 

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 
        && config.test.metadataStatement.tcDisplayContentType === 'text/plain') {
            it('content is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'text/plain',
                                'content': null
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('content is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'text/plain',
                                'content': undefined
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('content is empty DOMString', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'text/plain',
                                'content': ''
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        }
    })

    it(`F-5

        If Authenticator supports "text/plain" for Transaction confirmation: Send AuthenticationRequest containing "text/plain" Transaction with "content" field is NOT of type DOMString, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error   

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0
        && config.test.metadataStatement.tcDisplayContentType === 'text/plain') {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    data[0].transaction = [
                        {
                            'contentType': 'text/plain',
                            'content': 0xdeadbeef
                        }
                    ]

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        }
    })

    it(`F-6

        If Authenticator supports "text/plain" for Transaction confirmation: Send AuthenticationRequest containing "text/plain" Transaction with "content" field is NOT Base64URL encoded, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error   

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0
        && config.test.metadataStatement.tcDisplayContentType === 'text/plain') {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {
                    data[0].transaction = [
                        {
                            'contentType': 'text/plain',
                            'content': btoa('THIS IS TEST AND ITS COMPLETELY NOT FUNNY, SO PLEASE ACCEPT THE TRANSACTION!')
                        }
                    ]

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        }
    })

    it(`F-7

        If Authenticator supports "text/plain" for Transaction confirmation: Send AuthenticationRequest containing "text/plain" Transaction with "content" set to Base64URL encoded text of length more than 200 characters, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error 

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 
        && config.test.metadataStatement.tcDisplayContentType === 'text/plain') {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {

                    data[0].transaction = [
                        {
                            'contentType': 'text/plain',
                            'content': stringToBase64URL('Are you sure you want to send 200$ to the wine seller, who sold you Sauvignon-blanc, from 1994 crop, and the seller was from Taumatawhakatangihangakoauauotamateaturipukakapikimaungahoronukupokaiwhenuakitanatahu?')
                        }
                    ]

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        }
    })

    describe(`F-8

        If Authenticator supports "image/png" for Transaction confirmation: Send three AuthenticationRequests containing "image/png" Transaction, with "content" field set to "null", "undefined" and "empty" DOMString, wait for the responses, and check that API returns a PROTOCOL_ERROR(0x06) error for each of the response   

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 
        && config.test.metadataStatement.tcDisplayContentType === 'image/png') {
            it('content is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': null,
                                'tcDisplayPNGCharacteristics': config.test.metadataStatement.tcDisplayPNGCharacteristics[0]

                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('content is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': undefined,
                                'tcDisplayPNGCharacteristics': config.test.metadataStatement.tcDisplayPNGCharacteristics[0]

                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('content is empty DOMString', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': '',
                                'tcDisplayPNGCharacteristics': config.test.metadataStatement.tcDisplayPNGCharacteristics[0]
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        }
    })

    it(`F-9

        If Authenticator supports "image/png" for Transaction confirmation: Send AuthenticationRequest containing "image/png" Transaction with "content" field is NOT of type DOMString, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error 

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 
        && config.test.metadataStatement.tcDisplayContentType === 'image/png') {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {

                    data[0].transaction = [
                        {
                            'contentType': 'image/png',
                            'content': null,
                            'tcDisplayPNGCharacteristics': config.test.metadataStatement.tcDisplayPNGCharacteristics[0]

                        }
                    ]

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        }
    })

    it(`F-10

        If Authenticator supports "image/png" for Transaction confirmation: Send AuthenticationRequest containing "image/png" Transaction with "content" field is NOT Base64URL encoded, wait for the response, and check that API returns a PROTOCOL_ERROR(0x06) error 

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 
        && config.test.metadataStatement.tcDisplayContentType === 'image/png') {
            return getTestStaticJSON('Protocol-Auth-Req-P')
                .then((data) => {

                    data[0].transaction = [
                        {
                            'contentType': 'image/png',
                            'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8/L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N+QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE+CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9/NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A/hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V/pHDBYY1hrFGNuayJsym740u2C+02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT//ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs+ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK/cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta+x/+5Em0mzJ/+dGj/t8AyNmf2zvs9JmHt6vvmCpYtEFrcu+bYsc/m9lSGrTq9xWbtvveWGbZtMNm/ZarJt+w6rnft3u+45uy9s/4ODOYd+Hmk/Jn58xUnrU+fOJJ/9dX7SRe1LR68kXv13fc5Nm1t379TfU75/4mHeY7En+59lvhB5efB1/lv5dxc+NH0y/fzq64Lv4T8Ffp360/rP8f9/AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA+f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG+boA3e9jdF/P388r/AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v+4dCkW1PTEz2mapke6J/KMA7pOfOopkCZLZ/uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW/sMnJal5D+WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d/VzgM62jW3fI/paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy/AmRmmLecBkmBoowT6TI+bTYiK+67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC/R5s/BwAydO6pL0AlDgAAAABJRU5ErkJggg==',
                            'tcDisplayPNGCharacteristics': config.test.metadataStatement.tcDisplayPNGCharacteristics[0]

                        }
                    ]

                    let uafmessage = {
                        'uafProtocolMessage' : JSON.stringify(data),
                    }

                    return expectProcessUAFOperationFail(uafmessage);
                })
                .then((errorCode) => {
                    assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                })
        }
    })

    describe(`F-11

        If Authenticator supports "image/png" for Transaction confirmation: Send three AuthenticationRequests containing "image/png" Transaction, with "tcDisplayPNGCharacteristics" field set to "null", "undefined" and "empty" DICTIONARY, wait for the responses, and check that API returns a PROTOCOL_ERROR(0x06) error for each of the response  

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 
        && config.test.metadataStatement.tcDisplayContentType === 'image/png') {
            it('tcDisplayPNGCharacteristics is null', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': null
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })  

            it('content is undefined', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': undefined
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('content is empty DICTIONARY', () => {
                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': {}
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        }
    })

    describe(`F-12

        If Authenticator supports "image/png" for Transaction confirmation: Send a AuthenticationRequests containing "image/png" Transaction with: 
            (a) "tcDisplayPNGCharacteristics.width" that is NOT of type NUMBER 
            (b) "tcDisplayPNGCharacteristics.width" is undefined 
            (c) "tcDisplayPNGCharacteristics.height" that is NOT of type NUMBER 
            (d) "tcDisplayPNGCharacteristics.height" is undefined 
            (e) "tcDisplayPNGCharacteristics.bitDepth" that is NOT of type NUMBER 
            (f) "tcDisplayPNGCharacteristics.bitDepth" is undefined 
            (g) "tcDisplayPNGCharacteristics.colorType" that is NOT of type NUMBER 
            (h) "tcDisplayPNGCharacteristics.colorType" is undefined 
            (i) "tcDisplayPNGCharacteristics.compression" that is NOT of type NUMBER 
            (j) "tcDisplayPNGCharacteristics.compression" is undefined 
            (k) "tcDisplayPNGCharacteristics.filter" that is NOT of type NUMBER 
            (l) "tcDisplayPNGCharacteristics.filter" is undefined 
            (m) "tcDisplayPNGCharacteristics.interlace" that is NOT of type NUMBER 
            (n) "tcDisplayPNGCharacteristics.interlace" is undefined 
            (o) "tcDisplayPNGCharacteristics.plte" that is NOT of type SEQUENCE 
            (p) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with missing "r" field 
            (q) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with "r" field is NOT of type NUMBER 
            (r) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with missing "g" field 
            (s) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with "g" field is NOT of type NUMBER 
            (t) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with missing "b" field 
            (u) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with "b" field is NOT of type NUMBER 
            wait for the responses, and check that API returns a PROTOCOL_ERROR(0x06) error for each of the response    

    `, () => {
        if(config.test.metadataStatement.tcDisplay !== 0 
        && config.test.metadataStatement.tcDisplayContentType === 'image/png') {
            it('(a) "tcDisplayPNGCharacteristics.width" that is NOT of type NUMBER ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.width = '42';

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(b) "tcDisplayPNGCharacteristics.width" is undefined ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.width = undefined;

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(c) "tcDisplayPNGCharacteristics.height" that is NOT of type NUMBER ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.height = '42';

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(d) "tcDisplayPNGCharacteristics.height" is undefined ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.width = undefined;

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(e) "tcDisplayPNGCharacteristics.bitDepth" that is NOT of type NUMBER', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.bitDepth = '42';

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(f) "tcDisplayPNGCharacteristics.bitDepth" is undefined ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.bitDepth = undefined;

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(g) "tcDisplayPNGCharacteristics.colorType" that is NOT of type NUMBER ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.colorType = '42';

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(h) "tcDisplayPNGCharacteristics.colorType" is undefined ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.colorType = undefined;

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(i) "tcDisplayPNGCharacteristics.compression" that is NOT of type NUMBER ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.compression = '42';

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(j) "tcDisplayPNGCharacteristics.compression" is undefined ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.compression = undefined;

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(k) "tcDisplayPNGCharacteristics.filter" that is NOT of type NUMBER ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.filter = '42';

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(l) "tcDisplayPNGCharacteristics.filter" is undefined ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.filter = undefined;

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(m) "tcDisplayPNGCharacteristics.interlace" that is NOT of type NUMBER ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.interlace = '42';

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(n) "tcDisplayPNGCharacteristics.interlace" is undefined ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.interlace = undefined;

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(o) "tcDisplayPNGCharacteristics.plte" that is NOT of type SEQUENCE ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.plte = '[]';

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(p) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with missing "r" field ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.plte = [
                    {'r': 0x7F, 'g': 0x7F, 'b': 0x7F},
                    {'g': 0x7F, 'b': 0x7F}
                ];

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(q) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with "r" field is NOT of type NUMBER ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.plte = [
                    {'r': 0x7F, 'g': 0x7F, 'b': 0x7F},
                    {'r': '127', 'g': 0x7F, 'b': 0x7F}
                ];

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(r) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with missing "g" field ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.plte = [
                    {'r': 0x7F, 'g': 0x7F, 'b': 0x7F},
                    {'r': 0x7F, 'b': 0x7F}
                ];

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(s) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with "g" field is NOT of type NUMBER ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.plte = [
                    {'r': 0x7F, 'g': 0x7F, 'b': 0x7F},
                    {'r': 0x7F, 'g': '127', 'b': 0x7F}
                ];

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(t) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with missing "b" field ', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.plte = [
                    {'r': 0x7F, 'g': 0x7F, 'b': 0x7F},
                    {'r': 0x7F, 'g': 0x7F}
                ];

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })

            it('(u) "tcDisplayPNGCharacteristics.plte" contains "rgbPalletteEntry" with "b" field is NOT of type NUMBER', () => {
                let clonedTcDisplayPNGCharacteristics = Object.assign({}, config.test.metadataStatement.tcDisplayPNGCharacteristics[0]);

                clonedTcDisplayPNGCharacteristics.plte = [
                    {'r': 0x7F, 'g': 0x7F, 'b': 0x7F},
                    {'r': 0x7F, 'g': 0x7F, 'b': '127'}
                ];

                return getTestStaticJSON('Protocol-Auth-Req-P')
                    .then((data) => {

                        data[0].transaction = [
                            {
                                'contentType': 'image/png',
                                'content': 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg',
                                'tcDisplayPNGCharacteristics': clonedTcDisplayPNGCharacteristics
                            }
                        ]

                        let uafmessage = {
                            'uafProtocolMessage' : JSON.stringify(data),
                        }

                        return expectProcessUAFOperationFail(uafmessage);
                    })
                    .then((errorCode) => {
                        assert.equal(errorCode, 0x06, `Expected PROTOCOL_ERROR(0x06) error. Received ${INTERFACE_STATUS_CODES[errorCode]}(${errorCode})`)
                    })
            })
        }
    })
})
