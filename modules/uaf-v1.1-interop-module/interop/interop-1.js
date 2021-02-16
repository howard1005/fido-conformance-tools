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

        Interop-1

    `, function() {

    this.timeout(20000);

    let username = config.test.username;

    it('Test registration', () => {
        return rest.register.get(1200, username)
            .then((response) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(response),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
            .then((response) => {
                return rest.register.post(response.uafProtocolMessage, 1200, username)
            })
    })

    it('Test authentication', () => {
        return rest.authenticate.get(1200, username)
            .then((response) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(response),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
            .then((response) => {
                return rest.authenticate.post(response.uafProtocolMessage, 1200, username)
            })
    })

    let randomTransaction = `Send ${generateSecureRandomInt(100, 1000)} to ${generateRandomName()}?`;
    it(`Test Transaction Confirmation: \n${randomTransaction}`, () => {
        return rest.authenticate.get(1200, username, randomTransaction)
            .then((response) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(response),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
            .then((response) => {
                return rest.authenticate.post(response.uafProtocolMessage, 1200, username)
            })
    })

    it('Test Deregistration', () => {
        return rest.deregister.get(1200, username)
            .then((response) => {
                let uafmessage = {
                    'uafProtocolMessage' : JSON.stringify(response),
                }

                return expectProcessUAFOperationSucceed(uafmessage);
            })
    })

    it('Test get Auth resp from Client after dereg', () => {
        let uafMessage = {
            'uafProtocolMessage': JSON.stringify([
                {
                    "header": {
                        "upv": { "major": 1, "minor": 1 },
                        "op": "Auth",
                        "appID": "https://uaf.example.com",
                        "serverData": "5s7n8-7_LDAtRIKKYqbAtTTOezVKCjl2mPorYzbpxRrZ-_3wWroMXsF_pLYjNVm_l7bplAx4bkEwK6ibil9EHGfdfKOQ1q0tyEkNJFOgqdjVmLioroxgThlj8Istpt7q"
                    },
                    "challenge": generateRandomString(),
                    "policy": {
                        "accepted": [
                            [
                                {"aaid": [config.test.aaid]}
                            ]
                        ]
                    }
                }
            ])
        }

        return expectProcessUAFOperationFail(uafMessage)
    })

    it('Test get Auth req from Server after dereg', () => {
        return rest.deregister.get(1498, username)
    })

    it('Test deregister with unknown KeyID', () => {
        let uafMessage = {
            'uafProtocolMessage': JSON.stringify([
                {
                    "header": {
                        "op": "Dereg",
                        "upv": {
                            "major": 1,
                            "minor": 1
                        },
                        "appID": ""
                    },
                    "authenticators": [
                        {
                            "aaid": config.test.aaid,
                            "keyID": generateRandomBase64urlBytes(32)
                        }
                    ]
                }
            ])
        }

        return expectProcessUAFOperationSucceed(uafMessage)
    })

    it('Test deregister with unknown AAID', () => {
        let uafMessage = {
            'uafProtocolMessage': JSON.stringify([
                {
                    "header": {
                        "op": "Dereg",
                        "upv": {
                            "major": 1,
                            "minor": 1
                        },
                        "appID": ""
                    },
                    "authenticators": [
                        {
                            "aaid": generateRandomAAID(),
                            "keyID": generateRandomBase64urlBytes(32)
                        }
                    ]
                }
            ])
        }

        return expectProcessUAFOperationSucceed(uafMessage)
    })

    it('Test deregister ALL', () => {
        let uafMessage = {
            'uafProtocolMessage': JSON.stringify([
                {
                    "header": {
                        "op": "Dereg",
                        "upv": {
                            "major": 1,
                            "minor": 1
                        },
                        "appID": ""
                    },
                    "authenticators": [
                        {
                            "aaid": "",
                            "keyID": ""
                        }
                    ]
                }
            ])
        }

        return expectProcessUAFOperationSucceed(uafMessage)
    })
})
