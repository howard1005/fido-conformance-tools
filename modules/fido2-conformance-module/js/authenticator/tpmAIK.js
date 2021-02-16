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

/* ----- HELPERS ----- */
    let DERBoolean = (arg) => {
        return new jsrsasign.KJUR.asn1.DERBoolean()
    }

    let DERInteger = (arg) => {
        return new jsrsasign.KJUR.asn1.DERInteger(arg)
    }

    let DERIntegerHex = (arg) => {
        return new jsrsasign.KJUR.asn1.DERInteger({'hex': arg})
    }

    let DERIntegerPositiveHex = (arg) => {
        if(!!(128 & parseInt(arg.slice(0,2), 16))) //If highest bit is set
            arg = '00' + arg;

        return new jsrsasign.KJUR.asn1.DERInteger({'hex': arg})
    }

    let DEREnumerated = (arg) => {
        return new jsrsasign.KJUR.asn1.DEREnumerated(arg)
    }

    let DERBitString = (arg) => {
        let hexValue = hex.encode(arg);
        return new jsrsasign.KJUR.asn1.DERBitString({'hex': hexValue})
    }

    let DERBitStringObject = (arg) => {
        return new jsrsasign.KJUR.asn1.DERBitString({'obj': arg})
    }

    let DERBitStringBin = (arg) => {
        return new jsrsasign.KJUR.asn1.DERBitString({'bin': arg})
    }

    let DEROctetString = (arg) => {
        return new jsrsasign.KJUR.asn1.DEROctetString({'str': arg})
    }

    let DEROctetStringObj = (arg) => {
        return new jsrsasign.KJUR.asn1.DEROctetString({'hex': arg.getEncodedHex()})
    }

    let DEROctetStringHex = (arg) => {
        return new jsrsasign.KJUR.asn1.DEROctetString({'hex': arg})
    }

    let DERNull = (arg) => {
        return new jsrsasign.KJUR.asn1.DERNull()
    }

    let DERObjectIdentifier = (arg) => {
        return new jsrsasign.KJUR.asn1.DERObjectIdentifier({'oid': arg})
    }

    let DERUTF8String = (arg) => {
        return new jsrsasign.KJUR.asn1.DERUTF8String({'str': arg})
    }

    let DERNumericString = (arg) => {
        return new jsrsasign.KJUR.asn1.DERNumericString({'str': arg})
    }

    let DERPrintableString = (arg) => {
        return new jsrsasign.KJUR.asn1.DERPrintableString({'str': arg})
    }

    let DERTeletexString = (arg) => {
        return new jsrsasign.KJUR.asn1.DERTeletexString({'str': arg})
    }

    let DERIA5String = (arg) => {
        return new jsrsasign.KJUR.asn1.DERIA5String({'str': arg})
    }

    let DERBMPString = (arg) => {
        let stringBuffer = stringToArrayBuffer(arg);
        let finalBuffer = new Uint8Array();

        for(let byte of stringBuffer) {
            finalBuffer = mergeArrayBuffers(finalBuffer, new Uint8Array([0x00, byte]));
        }

        return DERTaggedObject('1e', ASN1Object(hex.encode(finalBuffer)))
    }

    let DERUTCTime = (arg) => {
        return new jsrsasign.KJUR.asn1.DERUTCTime({'date': arg})
    }

    let DERGeneralizedTime = (arg) => {
        return new jsrsasign.KJUR.asn1.DERGeneralizedTime({'date': arg})
    }

    let DERGeneralizedString = (arg) => {
        return new jsrsasign.KJUR.asn1.DERGeneralizedString({'str': arg})
    }

    let DERSequence = (arg) => {
        return new jsrsasign.KJUR.asn1.DERSequence({'array': arg})
    }

    let DERSet = (arg) => {
        return new jsrsasign.KJUR.asn1.DERSet({'array': arg})
    }

    let ASN1Object = (hex) => {
        let obj = new jsrsasign.KJUR.asn1.ASN1Object()
        obj.hTLV = hex;

        return obj
    }

    let DERTaggedObject = (id, obj) => {
        let newTagObj = new jsrsasign.KJUR.asn1.DERTaggedObject();
        newTagObj.setASN1Object(true, id, obj)
        return newTagObj
    }
/* ----- HELPERS END ----- */

/* ----- TBS ----- */
    let generateVersion = () => {
        let num = DERInteger(2);
        return DERTaggedObject('a0', num)
    }

    let generateSerial = () => {
        let serial = generateRandomBuffer(14);
        let serialHex = '04' + hex.encode(serial);

        return DERIntegerHex(serialHex)
    }

    let generateAlgorithmIdentifier = (hashingAlg) => {
        if(hashingAlg === 'SHA-256')
            return DERSequence([DERObjectIdentifier('1.2.840.113549.1.1.11'), DERNull()]) //sha256WithRSAEncryption
        else if(hashingAlg === 'SHA-1')
            return DERSequence([DERObjectIdentifier('1.2.840.113549.1.1.5'), DERNull()]) //sha1WithRSAEncryption
        else 
            return DERSequence([DERObjectIdentifier('1.2.840.113549.1.1.1'), DERNull()]) //RSAEncryption
    }

    let generateIssuer = (issuerCommonName) => {
        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERPrintableString(issuerCommonName)
        ])])

        return DERSequence([commonName])
    }

    let generateTimeStamps = () => {
        let start = DERUTCTime(new Date(Date.UTC(2018, 1, 1, 0, 0, 0, 0)));
        let end   = DERUTCTime(new Date(Date.UTC(2025, 0, 31, 23, 59, 59, 0)));

        return DERSequence([start, end])
    }
    let generateSubject = () => {
        return DERSequence([])
    }

    let generatePublicKeyInfo = (publicKeyBuffer) => {
        publicKeyBuffer = mergeArrayBuffers(new Uint8Array([0x00]), publicKeyBuffer);
        let identifier  = generateAlgorithmIdentifier()


        let publicKeyHex = hex.encode(publicKeyBuffer);
        let publicKeyBitString = DERBitStringObject({
            'seq': [
                {'int': {'hex': publicKeyHex}},
                {'int': 65537}
            ]
        })
        return DERSequence([identifier, publicKeyBitString])
    }

    let generateExtensions = (subjectPublicKeyBuffer, authorityPublicKeyBuffer, issuerCommonName) => {
        /* KEY USAGE */
        let keyUsageSequence = DERSequence([
            DERObjectIdentifier('2.5.29.15'),
            DERBoolean(),
            DEROctetStringObj(DERBitStringBin('1'))
        ])

        let basicConstraint = DERSequence([
            DERObjectIdentifier('2.5.29.19'),
            DERBoolean(),
            DEROctetStringObj(DERSequence([]))
        ])

        let certificatePolicies = DERSequence([
            DERObjectIdentifier('2.5.29.32'),
            DERBoolean(),
            DEROctetStringObj(DERSequence([
                DERSequence([
                    DERObjectIdentifier('1.3.6.1.4.1.311.21.31'),
                    DERSequence([DERSequence([
                        DERObjectIdentifier('1.3.6.1.5.5.7.2.2'),
                        DERSequence([
                            DERBMPString('FAKE FIDO TCPA Trusted Platform Identity')
                        ])
                    ])])
                ])
            ]))
        ])

        let extKeyUsage = DERSequence([
            DERObjectIdentifier('2.5.29.37'),
            DEROctetStringObj(DERSequence([
                DERObjectIdentifier('2.23.133.8.3')
            ]))
        ])

        let subjectAltName = DERSequence([
            DERObjectIdentifier('2.5.29.17'),
            DERBoolean(),
            DEROctetStringObj(DERSequence([
                DERTaggedObject('a4', DERSequence([DERSet([
                    DERSequence([
                        DERObjectIdentifier('2.23.133.2.3'),  // tcpaTpmVersion
                        DERUTF8String('id:13')
                    ]),
                    DERSequence([
                        DERObjectIdentifier('2.23.133.2.2'), // tcpaTpmModel
                        DERUTF8String('NPCT6xx')
                    ]),
                    DERSequence([
                        DERObjectIdentifier('2.23.133.2.1'),  // tcpaTpmManufacturer
                        DERUTF8String('id:FFFFF1D0')
                    ])
                ])]))
            ]))
        ])


        let authorityPKBitStringValue = DERSequence([
            DERIntegerPositiveHex(hex.encode(authorityPublicKeyBuffer)),
            DERInteger(65537)
        ])
        let authorityKeyIdBuffer = window.navigator.fido.fido2.crypto.hash('sha1', hex.decode(authorityPKBitStringValue.getEncodedHex()));
        let authorityKeyIdHex    = hex.encode(authorityKeyIdBuffer);
        let authorityKeyIndentifier = DERSequence([
            DERObjectIdentifier('2.5.29.35'),
            DEROctetStringObj(DERSequence([DERTaggedObject('80', ASN1Object(authorityKeyIdHex))]))
        ])

        let subjectPKBitStringValue = DERSequence([
            DERIntegerPositiveHex(hex.encode(subjectPublicKeyBuffer)),
            DERInteger(65537)
        ])
        let subjectKeyIdBuffer    = window.navigator.fido.fido2.crypto.hash('sha1', hex.decode(subjectPKBitStringValue.getEncodedHex()));
        let subjectKeyIndentifier = DERSequence([
            DERObjectIdentifier('2.5.29.14'),
            DEROctetStringObj(DEROctetStringHex(hex.encode(subjectKeyIdBuffer)))
        ])

        let authorityInfoAccess = DERSequence([
            DERObjectIdentifier('1.3.6.1.5.5.7.1.1'),
            DEROctetStringObj(DERSequence([DERSequence([
                DERObjectIdentifier('1.3.6.1.5.5.7.48.2'),
                DERTaggedObject('86', ASN1Object(hex.encode(UTF8toBuffer(`https://pki.certinfra.fidoalliance.org/tpm/${issuerCommonName}.crt`))))
            ])]))
        ])

        let cRLDistributionPoints = DERSequence([
            DERObjectIdentifier('2.5.29.31'),
            DEROctetStringObj(DERSequence([DERSequence([
                DERTaggedObject('a0', DERTaggedObject('a0', DERTaggedObject('86', ASN1Object(hex.encode(UTF8toBuffer(`https://pki.certinfra.fidoalliance.org/tpm/crl/${issuerCommonName}.crl`))))))
            ])]))
        ])

        let finalSequence = DERSequence([keyUsageSequence, basicConstraint, certificatePolicies, extKeyUsage, subjectAltName, authorityKeyIndentifier, subjectKeyIndentifier, authorityInfoAccess, cRLDistributionPoints])
        return DERTaggedObject('a3', finalSequence)
    }

    let generateTBS = (hashingAlg, subjectPublicKeyBuffer, authorityPublicKeyBuffer, issuerCommonName) => {
        return DERSequence([
            generateVersion(),
            generateSerial(),
            generateAlgorithmIdentifier(hashingAlg),
            generateIssuer(issuerCommonName),
            generateTimeStamps(),
            generateSubject(),
            generatePublicKeyInfo(subjectPublicKeyBuffer),
            generateExtensions(subjectPublicKeyBuffer, authorityPublicKeyBuffer, issuerCommonName)
        ])
    }

/* ----- TBS ENDS ----- */
    window.generateTPMAIK = (hashingAlg, authorityPrivateKeyJWT, subjectPublicKeyJWTStruct, issuerCommonName) => {
        let tbs = generateTBS('SHA-256', base64url.decode(subjectPublicKeyJWTStruct.n), base64url.decode(authorityPrivateKeyJWT.n), issuerCommonName)
        let algorithmIdentifier = generateAlgorithmIdentifier('SHA-256');
        let tbsBuffer           = hex.decode(tbs.getEncodedHex());

        return window.navigator.fido.fido2.crypto.signWithRSAKeyAsync('RSASSA-PKCS1-v1_5', 'SHA-256', authorityPrivateKeyJWT, tbsBuffer)
            .then((signatureBuffer) => {
                let signatureBitString = DERBitString(mergeArrayBuffers(new Uint8Array([0x00]), signatureBuffer));

                let certificate = DERSequence([tbs, algorithmIdentifier, signatureBitString])
                let certificateHex = certificate.getEncodedHex();

                return hex.decode(certificateHex)
            })
    }
})()

//  let tpmEKPrivateKey = {
//     'publicKey': {
//         'alg': 'RS256',
//         'e': 'AQAB',
//         'ext': true,
//         'key_ops': [
//             'verify'
//         ],
//         'kty': 'RSA',
//         'n': '1z5zfRGlB378sKiIsltfPe3--pyI4ii_CN7Pv38O1WCLwb0-H608v6ULS54UYExI9wp39EN1IV7ZAJhB317QO2IXGtr65YZrSiUjWEcjtsrYbM0BlJMoRvCCql_y9cxD7tI9qODo9_FI4sf82PbJ3q2Q2RRJ2Ua1Z9jxcYHef6r76e3dQd1RBYS2BShN7lpsFewbsxBK5M2hp3e_q-T60t3RbjiK8zqlsWoVQdyHHyYYsCkKmOVVet9E5oKhz0T3WEb0H5Y296QnR0zqQnrnwfLvKxxDol2ogSiViiMK1ZpY2bBx-_744TUDH_hRvbiCXeGkH0Q5wELOlvhQWYthQQ'
//     },
//     'privateKey': {
//         'alg': 'RS256',
//         'd': 'mzJmZymPyoXfgSkj1yZW1_qAvQadFCS5CZZOSQ8-DNBeNMVUw9ZPVQeVy2Ih4wVeHvInZ7I0BGm1Id6msH5WulqRukVmXpS7S2zXvVEeCTDdOCXhG9W3Vt8X9-zS7DPqT4q79sakdBI_sXTtdSsMh0iyhjNAxC9doZElFejEG1xFX3kHVPqQNG_kzFuCy02p_LY2o6qQKbMsaTISxmD3EFgh6-xG5JFxPOu9Akgf5sW0KxIqdhsUKbTSKPPQBoRsfn7kqnNAZswhexKCvJHDpbNlD2zWSOuKx_IHIuvErT5UHkq-1FwMX3YGwBrSaL-eRXk872m4ejU67h_7Xj9S2Q',
//         'dp': 'YnFkG1Rqq3wbGWSthGCX_29yZMsJKZsKGWYWE0E9SLbDL36cHzEIwr5yGMlR7FpF7wKVCfkvMOq36WZWICB-QKKABpGu6nMoNlZlNampPVbouHaRx-PXeXcJrF1Qsgr7h4NJQJ2YddkwUPZvhUN6Gad4_kCgSxSmtj3URPUsZ3U',
//         'dq': 'NzOkytzgN3NjH2LHiBCPOAOsEdj7GZuT4xXq17K7UW5hdl6ZyTOeclXOFRnvXYWPIfqg3OM-YVvYrA7nV4Opq0rAKL86d3OnuBeezawkz1m98PnXQC3JZpmJ7QNX7CF2tT-u7F3KpuNQ1vngU4ck-F7qTmCyZjPuWv7xpXaJuxM',
//         'e': 'AQAB',
//         'ext': true,
//         'key_ops': [
//             'sign'
//         ],
//         'kty': 'RSA',
//         'n': '1z5zfRGlB378sKiIsltfPe3--pyI4ii_CN7Pv38O1WCLwb0-H608v6ULS54UYExI9wp39EN1IV7ZAJhB317QO2IXGtr65YZrSiUjWEcjtsrYbM0BlJMoRvCCql_y9cxD7tI9qODo9_FI4sf82PbJ3q2Q2RRJ2Ua1Z9jxcYHef6r76e3dQd1RBYS2BShN7lpsFewbsxBK5M2hp3e_q-T60t3RbjiK8zqlsWoVQdyHHyYYsCkKmOVVet9E5oKhz0T3WEb0H5Y296QnR0zqQnrnwfLvKxxDol2ogSiViiMK1ZpY2bBx-_744TUDH_hRvbiCXeGkH0Q5wELOlvhQWYthQQ',
//         'p': '69LFfEo93snYQ4VezOjacIu0W2EN_Gic8lI6XYe-Xd-8FhmsUv4I1NFG5zweXv-Ns6-QbW15T3ZXb839U_91-FV-1x_F3344C9CSiZ5CzXPh-b4bfxHxClXbA5CoIL93oTeSSvX10F4Ut_4O5OkH7UzGNMDmE8WNOvm3czQFbuc',
//         'q': '6ajuM3L7B1Fw03i7WN-ICXBzby1egMexRlmdUTFWqKT-YCGZpk7tww8R0ofz0mF2uZOdg5Cc9AQzQTAFqWCHsinjhQqE8lx6nSnt3eORrM8HxDVgWHFAtHhxu1Zwp-D2Z8aHnWbG_Aw7GSkTe-phpLImvp-idsmgxyj_wjslcZc',
//         'qi': 'cAgRckONx515TQu1adEBWBnZlpdKfBEViqrLO_icHamcY_GfbHsrogYxa8DIZ1db6ccxnrIcarx0Un_aA8XT3Q5TYs7RPoydxG7zS6psGzYqyvVJXHhvduIm42BNevjmiHIHnpV90TRc9do2o17QYpko0d0E4-_szR_oIylu4pg'
//     },
//     'commonName': 'NCU-NTC-KEYID-FF990338E187079A6CD6A03ADC57237445F6A49A'
// }


// window.navigator.fido.fido2.crypto.generateRSA2048KeypairAsync('RSASSA-PKCS1-v1_5', 'SHA-256')
//     .then((newKey) => {
//         return window.generateTPMAIK('SHA-256', tpmEKPrivateKey.privateKey, newKey.public, tpmEKPrivateKey.commonName)
//     })
//     .then((result) => {
//         console.log('TPM AIK', base64url.encode(result))
//     })

