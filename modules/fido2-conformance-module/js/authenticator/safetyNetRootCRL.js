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
        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERUTF8String('FIDO Alliances FAKE Root CA - S1')
        ])])

        return DERSequence([countryName, organisationName, commonName])
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

    let generateTBS = (subjectPublicKeyBuffer, authorityPublicKeyBuffer) => {
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
    window.generateSafetyNetRootCRL = (hashingAlg, authorityPrivateKeyJWT) => {
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


// const rootkey = {"public":{"alg":"RS256","e":"AQAB","ext":true,"key_ops":["verify"],"kty":"RSA","n":"uaM_IUnlAlLP0WF2Lh4Xm7vSc_UGB3D9cP9_wlcOivzVD2TMSYm7-EEdZnxw0mUioNQGs7iuAyrT3zuE25y2bTCowD3x_mKcPZ_ZNndqqcC8hG8OCAqmTFlI8X0xvrbjdxi7dm8RG_CnDH7cowEdpaIYIplKJ5tHnndRhxU6V8p-ZVwuhzhODtLICWRFodFt7WT-qqGJD4qJgyjoEtOz05NdrTYUcP3N8cRyeJgh5PUIfd1RfkV_NjNdzXvNonUqnTKUXNq7PrsiJFaLgqMHrEcWGTARfinV8ZAS81CsXwVB2jeWdHBtqD0yIzjG6DH1SKSAV6cOim_BYHAZ-8MEcQ"},"private":{"alg":"RS256","d":"Ovz1vYU2oSNhaB45KHRlehYXzMMKVGkCD9sQZNe3BlFK_qZACAodUciXKA7Y5vI-K67UJl3D5bvBMYk_MW29xjqVFOlaMURyc16M7jLKEQDupoKHieSgbVhdxmbK3NhOtXSFdR_b5u30lxLk12MuYYh9dNkS6Dz-aAtwO6VyMZzbIgez6AXD9egx-sX8jetyZC5dKXAsJhTpcB3FyvSlU_sUCaLhNhjr8aNvNhCH15oB-RvLT4YSu5VUkuK-uiL_m40WSVN-kbjhQcANFH1lHDePyBtlzxvl-ZEkVEt899YAf0xp7-gE4CPTMgxFtVSoHpcVkkq6UcAowfHlnEQ8BQ","dp":"1lsRlU-152YBulJWrZzhBucyznYyNUxQdSLxKzDEio6j0DjDW2b4VAZWHhoNhB0-05OQQhFVupFxT6QG_eSk_iXebyXO2qgVYGnt4UILQVonki6uSB-ATH2bYybiXN_R0QtKPByrcQHAfnlGvneM83h6W7KpfJ4liajUvIVg8b8","dq":"U_D4hFOF_mu9wjXyG0BzTsf5u-KV5qx3oO6TSbUnRK1aEKQkLiihvzzpgiB1uQesPY-9d-NIofRjYRFGkpeB4E6K1t_US1AaYqBgyoaAnhmga-4AXXOF5QM9_in9qdljk1b6G20E-ekRFUJRYufc2fhc2KdNKsoCX08dqfOHFgc","e":"AQAB","ext":true,"key_ops":["sign"],"kty":"RSA","n":"uaM_IUnlAlLP0WF2Lh4Xm7vSc_UGB3D9cP9_wlcOivzVD2TMSYm7-EEdZnxw0mUioNQGs7iuAyrT3zuE25y2bTCowD3x_mKcPZ_ZNndqqcC8hG8OCAqmTFlI8X0xvrbjdxi7dm8RG_CnDH7cowEdpaIYIplKJ5tHnndRhxU6V8p-ZVwuhzhODtLICWRFodFt7WT-qqGJD4qJgyjoEtOz05NdrTYUcP3N8cRyeJgh5PUIfd1RfkV_NjNdzXvNonUqnTKUXNq7PrsiJFaLgqMHrEcWGTARfinV8ZAS81CsXwVB2jeWdHBtqD0yIzjG6DH1SKSAV6cOim_BYHAZ-8MEcQ","p":"4np731XPxFrRQPCyW0xEcWWtnyQcW_7JHqIMO7gJ6zRLyQ_5afCfDepKwpfzNwWDeON3-jqHm6AeYUPKTlsMKnR2AZxORK3IvXsK4Tttoku8cvDZ8GYOhORtI-T_nXyhApNkcFXPEVfG-xvCgU_DGLCp_OA42huJYuQZKhWj67c","q":"0dXrNsU1yv6u-2_gc8tzu6PxoAQ8W52YQSHbMKReRC7RqqiuxVAFO4qi2HZsnfd6ZHpmd3fYwhefvBVcjtGS2U6HXxrBve-rqPceRP17a99fIfmx5Z1j3k2yintxbzhOodNFwLxsOJOru_Q66ZAxO1UHYdpigbmlsJa8muEL4Rc","qi":"bm6p3xy5L1ba8SxBSIbWK88SoSolPB6VlnGKB7GK-CBPLMr7f8BcmdeuXiXSuzhvRnAe2HmCCaGAV4OAEmXFkK1nuk6WMZtz2rIkt2AGoeZA3kqLDmWXr-zBS933XCtm5v1Srhj10fqCGGGJAaVizBAj7Dy-z-xD5MEeqq28Ugw"}}

//     window.generateSafetyNetRootCRL('SHA-256', rootkey.private)
//     .then((CRLBuffer) => {
//         console.log('FIDO Fake Root Certificate Authority 2018.crt: ', base64StringCertToPEM(base64.encode(CRLBuffer)).replace(/CERTIFICATE/g, 'X509 CRL'))
//     })    
})()

