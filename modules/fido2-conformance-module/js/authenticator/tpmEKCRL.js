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
        return DERInteger(1);
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
        let keyId = hex.encode(generateRandomBuffer(20)).toUpperCase()
        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERPrintableString(issuerCommonName)
        ])])

        return DERSequence([commonName])
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

    let generateRevocationList = () => {
        let cert1 = DERSequence([
            DERIntegerHex('0426587D66EF02D0A20A20E4CE554136'),
            DERUTCTime(new Date(Date.UTC(2014, 2, 1, 0, 0, 0, 0))),
            DERSequence([DERSequence([
                DERObjectIdentifier('2.5.29.21'),
                DEROctetStringObj(DEREnumerated(0))
            ])])
        ])

        let cert2 = DERSequence([
            DERIntegerHex(hex.encode(generateRandomBuffer(16))),
            DERUTCTime(new Date(Date.UTC(2014, 3, 13, 0, 0, 0, 0))),
            DERSequence([DERSequence([
                DERObjectIdentifier('2.5.29.21'),
                DEROctetStringObj(DEREnumerated(0))
            ])])
        ])

        let cert3 = DERSequence([
            DERIntegerHex(hex.encode(generateRandomBuffer(16))),
            DERUTCTime(new Date(Date.UTC(2015, 2, 25, 0, 0, 0, 0))),
            DERSequence([DERSequence([
                DERObjectIdentifier('2.5.29.21'),
                DEROctetStringObj(DEREnumerated(0))
            ])])
        ])

        return DERSequence([cert1, cert2, cert3])
    }

    let generateExtensions = (authorityPublicKeyBuffer) => {
        /* KEY USAGE */
        let derCRLNumber = DERSequence([
            DERObjectIdentifier('2.5.29.20'),
            DEROctetStringObj(DERInteger(1))
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

        let finalSequence = DERSequence([derCRLNumber, authorityKeyIndentifier])
        return DERTaggedObject('a0', finalSequence)
    }

    let generateTBS = (hashingAlg, authorityPublicKeyBuffer, issuerCommonName) => {
        return DERSequence([
            generateVersion(),
            generateAlgorithmIdentifier(hashingAlg),
            generateIssuer(issuerCommonName),
            DERUTCTime(new Date(Date.UTC(2018, 1, 1, 0, 0, 0, 0))),
            DERUTCTime(new Date(Date.UTC(2020, 1, 1, 0, 0, 0, 0))),
            generateRevocationList(),
            generateExtensions(authorityPublicKeyBuffer)
        ])
    }

/* ----- TBS ENDS ----- */
    window.generateTPMREKCRL = (hashingAlg, authorityPrivateKeyJWT, issuerCommonName) => {
        let tbs = generateTBS(hashingAlg, base64url.decode(authorityPrivateKeyJWT.n), issuerCommonName)
        let algorithmIdentifier = generateAlgorithmIdentifier('SHA-256');
        let tbsBuffer           = hex.decode(tbs.getEncodedHex());

        return window.navigator.fido.fido2.crypto.signWithRSAKeyAsync('RSASSA-PKCS1-v1_5', 'SHA-256', authorityPrivateKeyJWT, tbsBuffer)
            .then((signatureBuffer) => {
                let signatureBitString = DERBitString(mergeArrayBuffers(new Uint8Array([0x00]), signatureBuffer));

                let crl = DERSequence([tbs, algorithmIdentifier, signatureBitString])
                let crlHex = crl.getEncodedHex();

                return hex.decode(crlHex)
            })
    }


// let tpmEKPrivateKey = {
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


// generateTPMREKCRL('SHA-256', tpmEKPrivateKey.privateKey, tpmEKPrivateKey.commonName)
//     .then((CRLBuffer) => console.log(`${tpmEKPrivateKey.commonName}.crl`, base64StringCertToPEM(base64.encode(CRLBuffer)).replace(/CERTIFICATE/g, 'X509 CRL')))
})()

