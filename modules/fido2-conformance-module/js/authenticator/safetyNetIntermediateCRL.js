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

    let generateAlgorithmIdentifier = () => {
        return DERSequence([DERObjectIdentifier('1.2.840.10045.4.3.3')]) //ecdsaWithSHA384
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

        let organisationUnitName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.11'),
            DERUTF8String('FAKE Metadata TOC Signing FAKE')
        ])])

        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERUTF8String('FAKE Root FAKE')
        ])])

        return DERSequence([countryName, organisationName, organisationUnitName, commonName])
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

    let generateTBS = (authorityPublicKeyBuffer) => {
        return DERSequence([
            generateVersion(),
            generateAlgorithmIdentifier(),
            generateIssuer(),
            DERUTCTime(new Date(Date.UTC(2020, 1, 1, 0, 0, 0, 0))),
            DERUTCTime(new Date(Date.UTC(2023, 1, 1, 0, 0, 0, 0))),
            generateRevocationList(),
            generateExtensions(authorityPublicKeyBuffer)
        ])
    }

/* ----- TBS ENDS ----- */
    window.generateSafetyNetIntermediateCRL = (hashingAlg, authorityPrivateKeyJWT) => {
        let tbs                 = generateTBS(base64url.decode(authorityPrivateKeyJWT.n))

        let algorithmIdentifier = generateAlgorithmIdentifier();

        let tbsBuffer          = hex.decode(tbs.getEncodedHex());
        let tbsHash            = window.navigator.fido.fido2.crypto.hash('sha384', tbsBuffer);


        return window.navigator.fido.fido2.crypto.signWithRSAKeyAsync('RSASSA-PKCS1-v1_5', hashingAlg, authorityPrivateKeyJWT, tbsBuffer)
        .then((signatureBuffer) => {
            let signatureBitString = DERBitString(mergeArrayBuffers(new Uint8Array([0x00]), signatureBuffer));

            let crl = DERSequence([tbs, algorithmIdentifier, signatureBitString])
            let crlHex = crl.getEncodedHex();

            return hex.decode(crlHex)
        })
    }


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

// window.generateSafetyNetIntermediateCRL('SHA-256', intermediatekey.private)
// .then((CRLBuffer) => {
//     console.log('attest.android.com.crl: ', base64StringCertToPEM(base64.encode(CRLBuffer)).replace(/CERTIFICATE/g, 'X509 CRL'))
// })

})()

