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

    let DEREnumerated = (arg) => {
        return new jsrsasign.KJUR.asn1.DEREnumerated(arg)
    }

    let DERBitString = (arg) => {
        let hexValue = hex.encode(arg);
        return new jsrsasign.KJUR.asn1.DERBitString({'hex': hexValue})
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

    let generateAlgorithmIdentifier = () => {
        return DERSequence([DERObjectIdentifier('1.2.840.10045.4.3.2')])
    }

    let generateIssuer = () => {
        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERUTF8String('FAKE Android Keystore Software Attestation Intermediate FAKE')
        ])])
        let emailAddress = DERSet([DERSequence([
            DERObjectIdentifier('1.2.840.113549.1.9.1'),
            DERIA5String('conformance-tools@fidoalliance.org'),
        ])])
        let organisationName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.10'),
            DERUTF8String('FIDO Alliance')
        ])])
        let organisationalUnitName  = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.11'),
            DERUTF8String('Authenticator Attestation')
        ])])
        let countryName  = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.6'),
            DERPrintableString('US'),
        ])])
        let stateOrProvinceName  = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.8'),
            DERUTF8String('MY'),
        ])])
        let localityName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.7'),
            DERUTF8String('Wakefield')
        ])])

        return DERSequence([commonName, emailAddress, organisationName, organisationalUnitName, countryName, stateOrProvinceName, localityName])
    }

    let generateTimeStamps = () => {
        let utcTime = DERUTCTime(new Date(Date.UTC(1970, 1, 1, 0, 0, 0, 0)))
        let generalisedTime = DERGeneralizedTime(new Date(Date.UTC(2099, 0, 31, 23, 59, 59, 0)))

        return DERSequence([utcTime, generalisedTime])
    }
    let generateSubject = () => {
        let commonName = DERSet([DERSequence([
            DERObjectIdentifier('2.5.4.3'),
            DERUTF8String('FAKE Android Keystore Key FAKE')
        ])])

        return DERSequence([commonName])
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


    let generateExtensions = (clientDataHashBuffer) => {
        let clientDataHashHex = hex.encode(clientDataHashBuffer);

        /* KEY USAGE */
        let keyUsageSequence = DERSequence([
            DERObjectIdentifier('2.5.29.15'),
            DEROctetStringObj(DERBitStringBin('1'))
        ])

        /* KEY_DESCRIPTION */
        let keyDescriptionSequence = DERSequence([
            DERInteger(2),     // attestationVersion
            DEREnumerated(0),  // attestationSecurityLevel
            DERInteger(1),     // keymasterVersion
            DEREnumerated(0),  // keymasterSecurityLevel
            DEROctetStringHex(clientDataHashHex), // attestationChallenge
            DEROctetStringHex(''), // reserved
            ASN1Object('3069BF853D080206015ED3E3CFA0BF85455904573055312F302D0428636F6D2E616E64726F69642E6B657973746F72652E616E64726F69646B657973746F726564656D6F0201013122042074CFCB507488F529108591C7A505919F327732FBC1D803526AEA980006D2D898'), //softwareEnforced
            ASN1Object('3032A1053103020102A203020103A30402020100A5053103020104AA03020101BF837803020102BF853E03020100BF853F020500') //teeEnforced
        ])

        let keyDescriptionObject = DERSequence([
            DERObjectIdentifier('1.3.6.1.4.1.11129.2.1.17'),
            DEROctetStringObj(keyDescriptionSequence)
        ])

        /* authorityKeyIdentifier */
        let authorityKeyIdentifier = DERSequence([
            DERObjectIdentifier('2.5.29.35'),
            DEROctetStringHex('30168014A3D2AA2CEF0D8CF22402D51CB460BCBF6A5B2414')
        ])
        let finalSequence = DERSequence([keyUsageSequence, keyDescriptionObject, authorityKeyIdentifier])
        return DERTaggedObject('a3', finalSequence)
    }

    let generateTBS = (publicKeyBuffer, clientDataHash) => {
        return DERSequence([
            generateVersion(),
            DERInteger(1),
            generateAlgorithmIdentifier(),
            generateIssuer(),
            generateTimeStamps(),
            generateSubject(),
            generatePublicKeyInfo(publicKeyBuffer),
            generateExtensions(clientDataHash)
        ])
    }
/* ----- TBS ENDS ----- */
    window.generateAndroidKeystoreAttestationCertificate = (privateKeyBuffer, publicKeyBuffer, clientDataHash) => {
        let tbs             = generateTBS(publicKeyBuffer, clientDataHash)

        let algorithmIdentifier = generateAlgorithmIdentifier();

        let tbsBuffer          = hex.decode(tbs.getEncodedHex());
        let tbsHash            = window.navigator.fido.fido2.crypto.hash('sha256', tbsBuffer);
        let signatureBuffer    = window.navigator.fido.fido2.crypto.signWithECDSAKeyDER('p256', privateKeyBuffer, tbsHash);
        let signatureBitString = DERBitString(mergeArrayBuffers(new Uint8Array([0x00]), signatureBuffer));

        let certificate = DERSequence([tbs, algorithmIdentifier, signatureBitString])
        let certificateHex = certificate.getEncodedHex();

        return hex.decode(certificateHex)
    }
})()
