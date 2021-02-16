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
        return DERSequence([DERObjectIdentifier('1.2.840.10045.4.3.2')]) //ecdsaWithSHA256
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
            DERUTF8String('FAKE CA-1 FAKE')
        ])])

        return DERSequence([countryName, organisationName, organisationUnitName, commonName])
    }

    let generateExtensions = (authorityPublicKeyBuffer) => {
        /* KEY USAGE */
        let derCRLNumber = DERSequence([
            DERObjectIdentifier('2.5.29.20'),
            DEROctetStringObj(DERInteger(1))
        ])

        let authorityKeyIndentifier = DERSequence([
            DERObjectIdentifier('2.5.29.35'),
            DEROctetStringObj(DERSequence([DERTaggedObject('80', ASN1Object(hex.encode(window.navigator.fido.fido2.crypto.hash('sha1', authorityPublicKeyBuffer))))]))
        ])

        let finalSequence = DERSequence([derCRLNumber, authorityKeyIndentifier])
        return DERTaggedObject('a0', finalSequence)
    }

    let generateRevocationList = () => {
        let cert1 = DERSequence([
            DERIntegerHex('04' + hex.encode(generateRandomBuffer(14))),
            DERUTCTime(new Date(Date.UTC(2016, 2, 1, 0, 0, 0, 0))),
            DERSequence([DERSequence([
                DERObjectIdentifier('2.5.29.21'),
                DEROctetStringObj(DEREnumerated(0))
            ])])
        ])

        let cert2 = DERSequence([
            DERIntegerHex('04' + hex.encode(generateRandomBuffer(14))),
            DERUTCTime(new Date(Date.UTC(2016, 3, 13, 0, 0, 0, 0))),
            DERSequence([DERSequence([
                DERObjectIdentifier('2.5.29.21'),
                DEROctetStringObj(DEREnumerated(0))
            ])])
        ])

        let cert3 = DERSequence([
            DERIntegerHex('04' + hex.encode(generateRandomBuffer(14))),
            DERUTCTime(new Date(Date.UTC(2017, 2, 25, 0, 0, 0, 0))),
            DERSequence([DERSequence([
                DERObjectIdentifier('2.5.29.21'),
                DEROctetStringObj(DEREnumerated(0))
            ])])
        ])

        let cert4 = DERSequence([
            DERIntegerHex('04806749DE307BBD5175A26D73F5F3'),
            DERUTCTime(new Date(Date.UTC(2018, 2, 25, 0, 0, 0, 0))),
            DERSequence([DERSequence([
                DERObjectIdentifier('2.5.29.21'),
                DEROctetStringObj(DEREnumerated(0))
            ])])
        ])

        return DERSequence([cert2, cert3, cert1, cert4])
    }

    let generateTBS = (subjectPublicKeyBuffer, authorityPublicKeyBuffer) => {
        return DERSequence([
            generateVersion(),
            generateAlgorithmIdentifier(),
            generateIssuer(),
            DERUTCTime(new Date(Date.UTC(2018, 1, 1, 0, 0, 0, 0))),
            DERUTCTime(new Date(Date.UTC(2022, 1, 1, 0, 0, 0, 0))),
            generateRevocationList(),
            generateExtensions(authorityPublicKeyBuffer)
        ])
    }

/* ----- TBS ENDS ----- */
    window.generateMDSIntermediateCRL = (privateKeyBuffer, publicKeyBuffer) => {
        let tbs                 = generateTBS(publicKeyBuffer, publicKeyBuffer)

        let algorithmIdentifier = generateAlgorithmIdentifier();

        let tbsBuffer          = hex.decode(tbs.getEncodedHex());
        let tbsHash            = window.navigator.fido.fido2.crypto.hash('sha256', tbsBuffer);
        let signatureBuffer    = window.navigator.fido.fido2.crypto.signWithECDSAKeyDER('p256', privateKeyBuffer, tbsHash);
        let signatureBitString = DERBitString(mergeArrayBuffers(new Uint8Array([0x00]), signatureBuffer));

        let certificate = DERSequence([tbs, algorithmIdentifier, signatureBitString])
        let certificateHex = certificate.getEncodedHex();

        return hex.decode(certificateHex)
    }

    // let intermediatekey = {"private": hex.decode("d84d821e81e351036e71e8bea8cb068768847ffa34215c944b38f039a095e185"), "public": hex.decode("04cb7dffcaa2accdb0fda77fe3bd0506598e19d8f783d6e8567a4012bbab9e37d6b6a860340433ee59ae64df6a95cfd42c3c53a80f0b11d1a92021fd62e310c4d1")}

    // console.log('MDS INTERMEDIATE CRL: ', base64.encode(generateMDSIntermediateCRL(intermediatekey.private, intermediatekey.public)))
})()
