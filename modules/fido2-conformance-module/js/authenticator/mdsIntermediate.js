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

    let generateSerial = (isRevoked) => {
        let serial = generateRandomBuffer(14);
        let serialHex = '04' + hex.encode(serial);
        if(isRevoked)
            serialHex = '0426587D66EF02D0A20A20E4CE554136';
        return DERIntegerHex(serialHex)
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

    let generateTimeStamps = () => {
        let start = DERUTCTime(new Date(Date.UTC(2017, 1, 1, 0, 0, 0, 0)));
        let end   = DERUTCTime(new Date(Date.UTC(2040, 0, 31, 23, 59, 59, 0)));

        return DERSequence([start, end])
    }

    let generateSubject = () => {
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

    let generatePublicKeyInfo = (publicKeyBuffer) => {
        publicKeyBuffer = mergeArrayBuffers(new Uint8Array([0x00]), publicKeyBuffer);
        let identifier  = DERSequence([
            DERObjectIdentifier('1.2.840.10045.2.1'),
            DERObjectIdentifier('1.2.840.10045.3.1.7')
        ])

        let publicKeyBitString = DERBitString(publicKeyBuffer);

        return DERSequence([identifier, publicKeyBitString])
    }

    let generateExtensions = (subjectPublicKeyBuffer, authorityPublicKeyBuffer) => {
        let keyUsageSequence = DERSequence([
            DERObjectIdentifier('2.5.29.15'),
            DEROctetStringObj(DERBitStringBin('0000011'))
        ])

        let basicConstraint = DERSequence([
            DERObjectIdentifier('2.5.29.19'),
            DERBoolean(),
            DEROctetStringObj(DERSequence([
                DERBoolean()
            ]))
        ])

        let subjectKeyIndentifier = DERSequence([
            DERObjectIdentifier('2.5.29.14'),
            DEROctetStringObj(DEROctetStringHex(hex.encode(window.navigator.fido.fido2.crypto.hash('sha1', subjectPublicKeyBuffer))))
        ])

        let authorityKeyIndentifier = DERSequence([
            DERObjectIdentifier('2.5.29.35'),
            DEROctetStringObj(DERSequence([DERTaggedObject('80', ASN1Object(hex.encode(window.navigator.fido.fido2.crypto.hash('sha1', authorityPublicKeyBuffer))))]))
        ])

        let cRLDistributionPoints = DERSequence([
            DERObjectIdentifier('2.5.29.31'),
            DEROctetStringObj(DERSequence([DERSequence([
                DERTaggedObject('a0', DERTaggedObject('a0', DERTaggedObject('86', ASN1Object(hex.encode(UTF8toBuffer('https://mds.certinfra.fidoalliance.org/crl/MDSROOT.crl'))))))
            ])]))
        ])

        let certificatePolicies = DERSequence([
            DERObjectIdentifier('2.5.29.32'),
            DEROctetStringObj(DERSequence([DERSequence([
                DERObjectIdentifier('1.3.6.1.4.1.45724.1.3.1'),
                DERSequence([DERSequence([
                    DERObjectIdentifier('1.3.6.1.5.5.7.2.1'),
                    DERIA5String('https://mds.certinfra.fidoalliance.org/repository')
                ])])
            ])]))
        ])

        let finalSequence = DERSequence([keyUsageSequence, basicConstraint, subjectKeyIndentifier, authorityKeyIndentifier, cRLDistributionPoints, certificatePolicies])
        return DERTaggedObject('a3', finalSequence)
    }

    let generateTBS = (subjectPublicKeyBuffer, authorityPublicKeyBuffer, isRevoked) => {
        return DERSequence([
            generateVersion(),
            generateSerial(isRevoked),
            generateAlgorithmIdentifier(),
            generateIssuer(),
            generateTimeStamps(),
            generateSubject(),
            generatePublicKeyInfo(subjectPublicKeyBuffer),
            generateExtensions(subjectPublicKeyBuffer, authorityPublicKeyBuffer)
        ])
    }

/* ----- TBS ENDS ----- */
    window.generateMDSIntermediateCertificate = (authorityPrivateKeyBuffer, subjectPublicKeyBuffer, authorityPublicKeyBuffer, isRevoked) => {
        let tbs                 = generateTBS(subjectPublicKeyBuffer, authorityPublicKeyBuffer, isRevoked)

        let algorithmIdentifier = generateAlgorithmIdentifier();

        let tbsBuffer          = hex.decode(tbs.getEncodedHex());
        let tbsHash            = window.navigator.fido.fido2.crypto.hash('sha384', tbsBuffer);
        let signatureBuffer    = window.navigator.fido.fido2.crypto.signWithECDSAKeyDER('p384', authorityPrivateKeyBuffer, tbsHash);
        let signatureBitString = DERBitString(mergeArrayBuffers(new Uint8Array([0x00]), signatureBuffer));

        let certificate = DERSequence([tbs, algorithmIdentifier, signatureBitString])
        let certificateHex = certificate.getEncodedHex();

        return hex.decode(certificateHex)
    }

    // let rootKey = {
    //     "private": hex.decode("ab4d8d6bacaa95c8efb356301c6ecf89628f9b13b7eb882ff8cde5b7c251777923307571810854345ddea8b36070fbfa"),
    //     "public": hex.decode("045c54b77aaf87e7347cece4adb37db83fff85fdfe806a9ac75156d67d89786580cf6f15868abe262daa6c24ab40f72e2860dea79f7998175d88b874582fcd4ed92c16a948d337093f110c17bf30126ab0fc1a4506c8b069a622d9adfc448d403e")
    // }

    // let intermediatekey = {"private": hex.decode("d84d821e81e351036e71e8bea8cb068768847ffa34215c944b38f039a095e185"), "public": hex.decode("04cb7dffcaa2accdb0fda77fe3bd0506598e19d8f783d6e8567a4012bbab9e37d6b6a860340433ee59ae64df6a95cfd42c3c53a80f0b11d1a92021fd62e310c4d1")}

    // console.log('MDS INTERMEDIATE: ', base64.encode(generateMDSIntermediateCertificate(rootKey.private, intermediatekey.public, rootKey.public)))
    // console.log('MDS INTERMEDIATE REVOKED: ', base64.encode(generateMDSIntermediateCertificate(rootKey.private, intermediatekey.public, rootKey.public, true)))
})()
