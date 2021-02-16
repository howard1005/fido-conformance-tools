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
        let organisationName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.10'),
            DERUTF8String('FIDO Alliance')
        ])])
        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERUTF8String('FIDO Alliances FAKE Root CA - S1')
        ])])

        return DERSequence([countryName, organisationName, commonName])
    }

    let generateTimeStamps = () => {
        let start = DERUTCTime(new Date(Date.UTC(2017, 1, 1, 0, 0, 0, 0)))
        let end = DERUTCTime(new Date(Date.UTC(2035, 0, 31, 23, 59, 59, 0)))

        return DERSequence([start, end])
    }

    let generateSubject = () => {
        let countryName  = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.6'),
            DERPrintableString('US'),
        ])])
        let organisationName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.10'),
            DERUTF8String('FIDO Alliances FAKE Trust Services')
        ])])
        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERUTF8String('FIDO Alliances FAKE Internet Authority F1')
        ])])

        return DERSequence([countryName, organisationName, commonName])
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

        let extKeyUsage = DERSequence([
            DERObjectIdentifier('2.5.29.37'),
            DEROctetStringObj(DERSequence([
                DERObjectIdentifier('1.3.6.1.5.5.7.3.1'),
                DERObjectIdentifier('1.3.6.1.5.5.7.3.2')
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
                DERTaggedObject('a0', DERTaggedObject('a0', DERTaggedObject('86', ASN1Object(hex.encode(UTF8toBuffer(encodeURI('https://pki.certinfra.fidoalliance.org/safetynet/crl/FIDO Fake Root Certificate Authority 2018.crl')))))))
            ])]))
        ])

        let authorityInfoAccess = DERSequence([
            DERObjectIdentifier('1.3.6.1.5.5.7.1.1'),
            DEROctetStringObj(DERSequence([DERSequence([
                DERObjectIdentifier('1.3.6.1.5.5.7.48.1'),
                DERTaggedObject('86', ASN1Object(hex.encode(UTF8toBuffer(encodeURI('https://pki.certinfra.fidoalliance.org/safetynet/FIDO Fake Root Certificate Authority 2018.crt')))))
            ])]))
        ])

        let certificatePolicies = DERSequence([
            DERObjectIdentifier('2.5.29.32'),
            DEROctetStringObj(DERSequence([
                DERSequence([
                    DERObjectIdentifier('2.23.140.1.2.2'),
                    DERSequence([DERSequence([
                        DERObjectIdentifier('1.3.6.1.5.5.7.2.1'),
                        DERIA5String('https://pki.certinfra.fidoalliance.org/safetynet/')
                    ])])
                ])
            ]))
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
    window.generateSafetyNetIntermediate = (hashingAlg, authorityPrivateKeyJWT, subjectPublicKeyJWTStruct) => {
        let tbs = generateTBS(hashingAlg, base64url.decode(subjectPublicKeyJWTStruct.n), base64url.decode(authorityPrivateKeyJWT.n))
        let algorithmIdentifier = generateAlgorithmIdentifier(hashingAlg);
        let tbsBuffer           = hex.decode(tbs.getEncodedHex());

        return window.navigator.fido.fido2.crypto.signWithRSAKeyAsync('RSASSA-PKCS1-v1_5', hashingAlg, authorityPrivateKeyJWT, tbsBuffer)
            .then((signatureBuffer) => {
                let signatureBitString = DERBitString(mergeArrayBuffers(new Uint8Array([0x00]), signatureBuffer));

                let certificate = DERSequence([tbs, algorithmIdentifier, signatureBitString])
                let certificateHex = certificate.getEncodedHex();

                return hex.decode(certificateHex)
            })
    }
})()

// const rootkey = {"public":{"alg":"RS256","e":"AQAB","ext":true,"key_ops":["verify"],"kty":"RSA","n":"uaM_IUnlAlLP0WF2Lh4Xm7vSc_UGB3D9cP9_wlcOivzVD2TMSYm7-EEdZnxw0mUioNQGs7iuAyrT3zuE25y2bTCowD3x_mKcPZ_ZNndqqcC8hG8OCAqmTFlI8X0xvrbjdxi7dm8RG_CnDH7cowEdpaIYIplKJ5tHnndRhxU6V8p-ZVwuhzhODtLICWRFodFt7WT-qqGJD4qJgyjoEtOz05NdrTYUcP3N8cRyeJgh5PUIfd1RfkV_NjNdzXvNonUqnTKUXNq7PrsiJFaLgqMHrEcWGTARfinV8ZAS81CsXwVB2jeWdHBtqD0yIzjG6DH1SKSAV6cOim_BYHAZ-8MEcQ"},"private":{"alg":"RS256","d":"Ovz1vYU2oSNhaB45KHRlehYXzMMKVGkCD9sQZNe3BlFK_qZACAodUciXKA7Y5vI-K67UJl3D5bvBMYk_MW29xjqVFOlaMURyc16M7jLKEQDupoKHieSgbVhdxmbK3NhOtXSFdR_b5u30lxLk12MuYYh9dNkS6Dz-aAtwO6VyMZzbIgez6AXD9egx-sX8jetyZC5dKXAsJhTpcB3FyvSlU_sUCaLhNhjr8aNvNhCH15oB-RvLT4YSu5VUkuK-uiL_m40WSVN-kbjhQcANFH1lHDePyBtlzxvl-ZEkVEt899YAf0xp7-gE4CPTMgxFtVSoHpcVkkq6UcAowfHlnEQ8BQ","dp":"1lsRlU-152YBulJWrZzhBucyznYyNUxQdSLxKzDEio6j0DjDW2b4VAZWHhoNhB0-05OQQhFVupFxT6QG_eSk_iXebyXO2qgVYGnt4UILQVonki6uSB-ATH2bYybiXN_R0QtKPByrcQHAfnlGvneM83h6W7KpfJ4liajUvIVg8b8","dq":"U_D4hFOF_mu9wjXyG0BzTsf5u-KV5qx3oO6TSbUnRK1aEKQkLiihvzzpgiB1uQesPY-9d-NIofRjYRFGkpeB4E6K1t_US1AaYqBgyoaAnhmga-4AXXOF5QM9_in9qdljk1b6G20E-ekRFUJRYufc2fhc2KdNKsoCX08dqfOHFgc","e":"AQAB","ext":true,"key_ops":["sign"],"kty":"RSA","n":"uaM_IUnlAlLP0WF2Lh4Xm7vSc_UGB3D9cP9_wlcOivzVD2TMSYm7-EEdZnxw0mUioNQGs7iuAyrT3zuE25y2bTCowD3x_mKcPZ_ZNndqqcC8hG8OCAqmTFlI8X0xvrbjdxi7dm8RG_CnDH7cowEdpaIYIplKJ5tHnndRhxU6V8p-ZVwuhzhODtLICWRFodFt7WT-qqGJD4qJgyjoEtOz05NdrTYUcP3N8cRyeJgh5PUIfd1RfkV_NjNdzXvNonUqnTKUXNq7PrsiJFaLgqMHrEcWGTARfinV8ZAS81CsXwVB2jeWdHBtqD0yIzjG6DH1SKSAV6cOim_BYHAZ-8MEcQ","p":"4np731XPxFrRQPCyW0xEcWWtnyQcW_7JHqIMO7gJ6zRLyQ_5afCfDepKwpfzNwWDeON3-jqHm6AeYUPKTlsMKnR2AZxORK3IvXsK4Tttoku8cvDZ8GYOhORtI-T_nXyhApNkcFXPEVfG-xvCgU_DGLCp_OA42huJYuQZKhWj67c","q":"0dXrNsU1yv6u-2_gc8tzu6PxoAQ8W52YQSHbMKReRC7RqqiuxVAFO4qi2HZsnfd6ZHpmd3fYwhefvBVcjtGS2U6HXxrBve-rqPceRP17a99fIfmx5Z1j3k2yintxbzhOodNFwLxsOJOru_Q66ZAxO1UHYdpigbmlsJa8muEL4Rc","qi":"bm6p3xy5L1ba8SxBSIbWK88SoSolPB6VlnGKB7GK-CBPLMr7f8BcmdeuXiXSuzhvRnAe2HmCCaGAV4OAEmXFkK1nuk6WMZtz2rIkt2AGoeZA3kqLDmWXr-zBS933XCtm5v1Srhj10fqCGGGJAaVizBAj7Dy-z-xD5MEeqq28Ugw"}}

// const intermediatekey = {
//     "public": {
//         "alg": "RS256",
//         "e": "AQAB",
//         "ext": true,
//         "key_ops": [
//             "verify"
//         ],
//         "kty": "RSA",
//         "n": "wQeYV9s3Kk-6r3iT5JIKJS9dK6aiVikdgeKQ9pXaNBtte8a4n7DzLHMcZREVlAt8IVWtNnbr15u9jak2WFRKk0lztKmGiVKv20KO4d0Yve68F2nFpmO-11UTrKflm8LHLH-ECC4R2R0-5USZ1UOvrhzrx3byiL_diwWchuoye5e_ymq8VqwaN1NYULdq4kZ27a_rmwFTi9ZysQV1iPQyDA4PSWhgdv7TMor3DF-Jk9RXwcRlsrANZ_mOi5pwl5ZnfbhYXUsc6NavEeCgNAGLOzapQUm8I2KexoJIzklLFC6UwZ1sNRRK9jeeKTOevI2s3p_85Gd-Tb4ojO1y3aQ4hw"
//     },
//     "private": {
//         "alg": "RS256",
//         "d": "phsvEYtm8VYixBTyz2KMsGsNth5y28oNxlN9g3R4jRZ9JGJhRaoz2DBGYwJMm1U2wEjGAXRchvFSMLFIPsJqWkx-8Rxg1ZL-GaQw6FQmkmr6GPvARerXst1XTOA-ScdXNgeVSqS6Xyc3lHtwFYFlkGL60m6dTugscRGnHMI0Jv1zXev5-umXTjfv43pqehlspcJgGD46YRb4uLmCMUx78UdxNVa1buJ4fRpEuTgWG-2IzHsSHw-7iWkq8_mZEveFDbpZYrg0ZDUxdrsMULinZCf1uLIGH8fgmdvY4YMrpo9Szl_Y8yBJzNkhzOcmopDMPXImPTurECVrjZnZ--I0YQ",
//         "dp": "S3CLHvVISsMHO8toV27EwKyHOUAYWhXoDUoT8M9Dn0FX94eJ8bgRw7uCDN8zBdeQOVFb10bV1-SAvOKO2I1aUKB9wifs8B5WT3IaCfRS3UnUDTiWYDIPpiU4hA-5V2L0WULwRrPScj7rNxfuqeEG1lN_1xQpfdTbnX03ucU_fmU",
//         "dq": "pJZUgUO61lq7-bCby4q2NwnOAkzEo792C2b73GjBekh_ghsvR-R9xhFcQL5-duBCojrKFpPQhRioAk5paYaJW9KHy6llCrKSCZp8ieRjENJpfNQqhcm28ojO-ehvHq20MHzl07WH7g8nYDKX3u0mcg2uqObPyBy4AGvwlOhKnZE",
//         "e": "AQAB",
//         "ext": true,
//         "key_ops": [
//             "sign"
//         ],
//         "kty": "RSA",
//         "n": "wQeYV9s3Kk-6r3iT5JIKJS9dK6aiVikdgeKQ9pXaNBtte8a4n7DzLHMcZREVlAt8IVWtNnbr15u9jak2WFRKk0lztKmGiVKv20KO4d0Yve68F2nFpmO-11UTrKflm8LHLH-ECC4R2R0-5USZ1UOvrhzrx3byiL_diwWchuoye5e_ymq8VqwaN1NYULdq4kZ27a_rmwFTi9ZysQV1iPQyDA4PSWhgdv7TMor3DF-Jk9RXwcRlsrANZ_mOi5pwl5ZnfbhYXUsc6NavEeCgNAGLOzapQUm8I2KexoJIzklLFC6UwZ1sNRRK9jeeKTOevI2s3p_85Gd-Tb4ojO1y3aQ4hw",
//         "p": "7lCvHoiRHaGzIjaw_JuhhSlWOi-Nal8kGJtlpBV5-Od709315Z4qDSUqIezMTzQfswUGM89-d22b93PEnDkxaHQSfi6iC70MyAHk2nE9TIofbg23gFz9gopWJanvdCt7YBF99aLGcsa8rLJBuBSKyg4LbwhsOCZrSS9TVH1jIgs",
//         "q": "z1qdPVvFT3SQliNrjuJX_9e14zH5bYbAN0KW_6YR2W15w04221iM1lK6B_dVts5NsC92IoRG6K3rit44OCP_dd8k8Hl_ZmrzZxJlZd-BVazc8BBBo3aVn_oF9UnhwodTtdVQsNMoCWegpNmEROvZfiPypZNX9z4lMKkOtWs4bPU",
//         "qi": "wk22_VOLUayG0eOPRR_RJmce17JWA21mYvcBpAchWrlRz1CNv86jm6hb-ud1xCOCkg8MAPf-hHP6jgeXQAaNOK38hMVftY-SWSnz6Pi5UTyynVgtqiIE53xiwgW2u5-X-L9OvZOJKLyznRAiYTsOUkmIX8XgwWQNGzHDtnOWVAI"
//     }
// }

// window.generateSafetyNetIntermediate('SHA-256', rootkey.private, intermediatekey.public)
//     .then((certBuffer) => console.log('SafetyNet intermediate: ', base64.encode(certBuffer)))

// window.navigator.fido.fido2.crypto.generateRSA2048KeypairAsync('RSASSA-PKCS1-v1_5', 'SHA-256')
//     .then((newKey) => {
//         console.log(newKey)
//         return window.generateSafetyNetIntermediate('SHA-256', issuerKey.private, newKey.public)
//     })
//     .then((result) => {
//         console.log(base64.encode(result))
//     })
