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

    let generateIssuer = () => {
        let countryName  = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.6'),
            DERPrintableString('US'),
        ])])
        let stateOrProvinceName  = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.8'),
            DERUTF8String('MY'),
        ])])
        let localityName  = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.7'),
            DERUTF8String('Wakefield'),
        ])])
        let organisationName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.10'),
            DERUTF8String('FIDO Alliance')
        ])])
        let organisationalUnitName  = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.11'),
            DERUTF8String('CWG')
        ])])
        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERUTF8String('FIDO Fake TPM Root Certificate Authority 2018')
        ])])
        let emailAddress = DERSet([DERSequence([
            DERObjectIdentifier('1.2.840.113549.1.9.1'),
            DERIA5String('conformance-tools@fidoalliance.org'),
        ])])

        return DERSequence([countryName, stateOrProvinceName, localityName, organisationName, organisationalUnitName, commonName, emailAddress])
    }

    let generateTimeStamps = () => {
        let start = DERUTCTime(new Date(Date.UTC(2017, 1, 1, 0, 0, 0, 0)))
        let end = DERUTCTime(new Date(Date.UTC(2035, 0, 31, 23, 59, 59, 0)))

        return DERSequence([start, end])
    }

    let generateSubject = () => {
        let keyId = hex.encode(generateRandomBuffer(20)).toUpperCase()
        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERPrintableString('NCU-NTC-KEYID-' + "FF990338E187079A6CD6A03ADC57237445F6A49A")
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


    let generateExtensions = (subjectPublicKeyBuffer, authorityPublicKeyBuffer) => {
        /* KEY USAGE */
        let keyUsageSequence = DERSequence([
            DERObjectIdentifier('2.5.29.15'),
            DEROctetStringObj(DERBitStringBin('1000011'))
        ])

        let certificatePolicies = DERSequence([
            DERObjectIdentifier('2.5.29.32'),
            DEROctetStringObj(DERSequence([
                DERSequence([
                    DERObjectIdentifier('1.3.6.1.4.1.311.21.31')
                ])
            ]))
        ])

        let extKeyUsage = DERSequence([
            DERObjectIdentifier('2.5.29.37'),
            DEROctetStringObj(DERSequence([
                DERObjectIdentifier('1.3.6.1.4.1.311.21.36'),
                DERObjectIdentifier('2.23.133.8.3')
            ]))
        ])

        let basicConstraint = DERSequence([
            DERObjectIdentifier('2.5.29.19'),
            DERBoolean(),
            DEROctetStringObj(DERSequence([
                DERBoolean(),
                DERInteger(0)
            ]))
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

        let cRLDistributionPoints = DERSequence([
            DERObjectIdentifier('2.5.29.31'),
            DEROctetStringObj(DERSequence([DERSequence([
                DERTaggedObject('a0', DERTaggedObject('a0', DERTaggedObject('86', ASN1Object(hex.encode(UTF8toBuffer('https://pki.certinfra.fidoalliance.org/tpm/crl/FIDO Fake TPM Root Certificate Authority 2018.crl'))))))
            ])]))
        ])

        let authorityInfoAccess = DERSequence([
            DERObjectIdentifier('1.3.6.1.5.5.7.1.1'),
            DEROctetStringObj(DERSequence([DERSequence([
                DERObjectIdentifier('1.3.6.1.5.5.7.48.2'),
                DERTaggedObject('86', ASN1Object(hex.encode(UTF8toBuffer('https://pki.certinfra.fidoalliance.org/tpm/FIDO Fake TPM Root Certificate Authority 2018.crt'))))
            ])]))
        ])

        let finalSequence = DERSequence([keyUsageSequence, certificatePolicies, extKeyUsage, basicConstraint, subjectKeyIndentifier, authorityKeyIndentifier, cRLDistributionPoints, authorityInfoAccess])
        return DERTaggedObject('a3', finalSequence)
    }

    let generateTBS = (hashingAlg, subjectPublicKeyBuffer, authorityPublicKeyBuffer) => {
        return DERSequence([
            generateVersion(),
            generateSerial(),
            generateAlgorithmIdentifier(hashingAlg),
            generateIssuer(),
            generateTimeStamps(),
            generateSubject(),
            generatePublicKeyInfo(subjectPublicKeyBuffer),
            generateExtensions(subjectPublicKeyBuffer, authorityPublicKeyBuffer)
        ])
    }

/* ----- TBS ENDS ----- */
    window.generateTPMEK = (hashingAlg, authorityPrivateKeyJWT, subjectPublicKeyJWTStruct) => {
        let tbs = generateTBS(hashingAlg, base64url.decode(subjectPublicKeyJWTStruct.n), base64url.decode(authorityPrivateKeyJWT.n))
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

// let rootKey = {
//     "kty": "RSA",
//     "n": "yCtbMw6ckWpylo7ZCboe3khforOB1eUb0DZg4mLsf460nKnZJbztZh_3qqLQTUBEb1kxeGW31QiJ5UoiAcPAoo9aHIADVfjJEPvr865fOqt85f_qO2qsF6ZjVpNk1_zQRP4xPRLZPhawQvZsnmV20vteV8K4KL9kWw_Yjo-m9LKt90OM1tf7-F_uh1alocxc-WPmfpXxSHDfySTvnq6m8cQySAn3LyjAg1pYnT4P9QC0HbNKz0KoL-EFylsmvps7wjAeRqNetu0BdmvBLtYC7AMxGpCzAuF5tYl-9_hWMI544QGnZrQnhIXfq704brI04NsUtBmCfZ5rEuc-Gzrz_asAPo6JSXyj9OSq-yPiWXen3g98_BI7f7gZoV6rqrdCojkFlWZVBJgWgHio0JEy7OB4RPO0SIKichjKbvIyTcE-J7oPCgz5UCjBbSo94sJ8hs35W2y8aVYriRZ94z5w9IM_T_tZLkZDOzI03uot-PO2d1xXK8YQ_QVzKnNcxXeve9l3x_CNzgknbp-IiL_NH509Zcn0YiGLfInHLPpEQ3p1PSU5vtx-mWWpoRWvzwYpQD907skC9exZjm16F1ZKu-cvboeA1AHAHC_tE26Lxema5F_pKXVFSu2XqK8JS6hO3EauL5ONaWxVIsQX4CIOxFdvS6mdmp8n-9SWr9FOuSM",
//     "e": "AQAB",
//     "d": "UQGKxNzS695iRR_GIbOarmYnndZ7Yq53VQnMp5FVGEIOQaBS6nzMrhmdxwZgugKaL12vMYQooyPzekFIBeLMYH0XAJWlw_MMm7z3vgQBMeMYhpPMnQMMZf3GEdFQbEA5oNIl5wtrsz7HUjIbvvZc4gEsKuP4VzUtTdTZ1Me5zylIUdqaco-xvtBD3a1pFlN4BM0zCGNx49kaF3LFLjiMAyddGd4-lG0vi3jSh8AIASSpv6NBUSMuoUG1cDD3OwfjZTDH79pJiEnd36i341ZklFKuWovYhf_tm1PreDqd1sSxko1yy5N4sp7i58OJxPKFh8HhXQk9z8x-lIXUknyHJJgIq6s0XVEBLKaQW17umcAadLEgabUiFgaAgpQ3a2tbyPqJq0enAcO7Zs8VoKyGjItkQ9YQpv9P1NwLe7AfdaXcCxMa9Tw6SFwozBxHFzeF-81MWPpWw5kU5lUBXNcCU-W_PYdB6CYwlT4FVR8u9Ar-blfKRxvPubpupdULWYDA5vxV9iAGT3s04knRO8GtBGOBSJf8Z0AO95jLjsd4uQmTxvmZzLrkFhbtJfDimlpZHY42DfJNMm9B8TtX544d9g1N7jrwqkPGb34_pecNxuk1w6GPQo4WjKGh8FrnjwE3CXeKN8SIqTkKg26zzVmi1btTtQ8v1z7Oow5vOn98RpE",
//     "p": "4uxMh21VXtrzfYa8rP2Qf0ckouWev3auV882JVwL6FuM94hckMLJrALGxdXbKz8-EJtXRgY5N43GbapPHxDYtlqnIuQ2NvhtqgKpAEIGd0Y85zSnoCB7mCmej5p-Lxph19wNc4inh2VOctc9KRzVJU-AI4qSYMw0Jdr0OBANYtFYICswouOQ0d3PK0Zqnso46dUVolUnDeLBLx3u2c2DACadXfrex-jVrpQNnWLBwfk8GE1cVAXio8_lmJuLj6AAdciETXwaPQOufbgpqS80Y72QZYV7JAn6FhyO5JZYyLTUOe6weiOE9dMmVS6hX7Ex5Q0O5zGLEmUqW1l8zE5wLQ",
//     "q": "4dF2eo0X87cm5Swj6HHCyTHw98l4uJpuzO668gTHiJ8wYDdNUriTMhCS0Gn7V7ZmOgztbJ5HC7IAoTgGsZtKovlsZ-2lw2_cqSpyCAPla0QAZV4JgXBguQC0oQehmJBwk5zVZWZRRUJkX4MhQcVWcW0SiTKJ7n95uPZR4QT1RsktWE2XJinPPdkBA3IwybBGvJ52QAN34dnOy9pWtgqt2IaQXB2-xekOETTDnZesBO5cnRw4KlN-2EvhMFzeEmdvLVVt6kMRfCS9L7cLfVHHBq2x9cRWrh2Ke9_aLHDOiNOXcJNpQiR5mEY2zIvjETRJDHXPAOIupL0WCJzOfjBQjw",
//     "dp": "yYL5utG2nBNnYrNB3YUWylANErNCM9hanhOei7KfyGl0V2S6frrbiGq2xXxRsqfon6qy57YjHVhDO6Ofu4CkUdtSzMNH-azHBdBy742yXDz9XHv_10zBNLDQ48lYANA2zw_UyiIyUyP9dDH7WAUIqqdcrTMjJd5w-KTldtuaZ4Rr87Um7Z-UPSnyDQXtLLF7tPrKyWtA0S3qS8MTFktP59RirtBXAcOb7fn_1SGb2ntPiG06bksDpmC6DLkkSBjYD8BO7NgmHMSmMXJXXKxUo7X1ApJ0dd5-PSCDLC7vDNy4EfIKuYvNSNeHFOHh4C5klnjwIRJ344_--zwOfQeyyQ",
//     "dq": "RiLrnIakENMq5nT-NhzXNewn_p35u8Rjc40WTUMEwj9HJCso_e9L8HnLT6YLJaQGPjNzro--WziPD4O6OIGV_eZgMCtUl83viC8hubGUGOvG_7TkWOqRcARzFaysGRmLjZ1hfhv4U_2Z9TxiIO5suc_5uNkUlBnNsY_3wF7s225yggGfV4AW2QvET9CwrIPuhHjnG1y4aFJg81m-Is5QTncE8Udf0FJhRyDPPOw1xlZON5HjM-o49G8k4wOFCcxMcJUfDWqFTLyQcfh1PhgfK8jZBA9WKMAOGgld1v22eDLXz2RJhfyUM6JjNMah4N8PbSpN_-VAPXRpGoWxcOoKqw",
//     "qi": "3Tu2XXqgR13q73i6mcvVOynSyeFw81NPHoEl3LaoKBs4LLUei7oXMkMsRXGy4O6MMsw6SCFpgSTrdXQQBWbMqdph0gJQ4Nnsty3quYWvaLlFG3vkc4mD7RrTWCRz3U9Xa3kXrlzFAoc8ppoXN6S2K0hCMjsXYWJOdk1lEVpRHegf4HYfhPtDP3ETd0KlfmyzZFH30KtZcGUQj9Tqjze4CnxsfR4VMBhnoyL3fUxxpfqTQkaL7lxJZKK6hWMYYlOLOlrzCpt5cZiBwni72VjH8pr14PI3BrEGQNao7GENDjZHQU-GNXe50KSX6CbpHJdw0SDx0-3INiY8PTOcD-AsSQ"
// }

// let EKKey = {
//     'public': {
//         'alg': 'RS256',
//         'e': 'AQAB',
//         'ext': true,
//         'key_ops': [
//             'verify'
//         ],
//         'kty': 'RSA',
//         'n': '1z5zfRGlB378sKiIsltfPe3--pyI4ii_CN7Pv38O1WCLwb0-H608v6ULS54UYExI9wp39EN1IV7ZAJhB317QO2IXGtr65YZrSiUjWEcjtsrYbM0BlJMoRvCCql_y9cxD7tI9qODo9_FI4sf82PbJ3q2Q2RRJ2Ua1Z9jxcYHef6r76e3dQd1RBYS2BShN7lpsFewbsxBK5M2hp3e_q-T60t3RbjiK8zqlsWoVQdyHHyYYsCkKmOVVet9E5oKhz0T3WEb0H5Y296QnR0zqQnrnwfLvKxxDol2ogSiViiMK1ZpY2bBx-_744TUDH_hRvbiCXeGkH0Q5wELOlvhQWYthQQ'
//     },
//     'private': {
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
//     }
// }

// generateTPMEK('SHA-256', rootKey, EKKey.public)
//     .then((certBuffer) => console.log('TPM EK: ', base64.encode(certBuffer)))
})()
