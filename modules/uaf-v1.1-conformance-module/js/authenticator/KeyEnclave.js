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
    /**
     * Crypto params for cryptographic signature operations
     * @type {Object}
     */
    let signatureAlgorithms = {
        'ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW': {
            'keyGeneration': {
                'type' : 'EC',
                'param': 'secp256r1'
            },
            'export': 'raw'
        },

        'ALG_SIGN_SECP256R1_ECDSA_SHA256_DER': {
            'keyGeneration': {
                'type' : 'EC',
                'param': 'secp256r1'
            },
            'export': 'der'
        },

        'ALG_SIGN_RSASSA_PSS_SHA256_RAW': {
            'keyGeneration': {
                'type' : 'RSA',
                'param': 2048
            },
            'export': 'raw'
        },

        'ALG_SIGN_RSASSA_PSS_SHA256_DER': {
            'keyGeneration': {
                'type' : 'RSA',
                'param': 2048
            },
            'export': 'der'
        },

        'ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW': {
            'keyGeneration': {
                'type' : 'EC',
                'param': 'secp256k1'
            },
            'export': 'raw'
        },

        'ALG_SIGN_SECP256K1_ECDSA_SHA256_DER': {
            'keyGeneration': {
                'type' : 'EC',
                'param': 'secp256k1'
            },
            'export': 'der'
        }
    }

    /**
     * Crypto params for public key export formats
     * @type {Object}
     */
    let publicKeyAlgorithms = {
        'ALG_KEY_ECC_X962_RAW': {
            'export': 'raw'
        },
        'ALG_KEY_ECC_X962_DER': {
            'export': 'der'
        },
        'ALG_KEY_RSA_2048_PSS_RAW': {
            'export': 'raw'
        },
        'ALG_KEY_RSA_2048_PSS_DER': {
            'export': 'der'
        }
    }

/* ----- CERT AND BATCH KEYPAIR ----- */
    let certs = {
        'RSA': {
            'cert': '-----BEGIN CERTIFICATE-----\n' +
                    'MIIDeDCCAmCgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQGEwJOWjEj\n' +
                    'MCEGA1UEAwwaRklETyBDb25mb3JtYWNlIFRlc3QgVG9vbHMxFjAUBgNVBAoMDUZJ\n' +
                    'RE8gQWxsaWFuY2UxJDAiBgNVBAsMG0NlcnRpZmljYXRpb24gV29ya2luZyBHcm91\n' +
                    'cDAeFw0xNzAzMDQxOTQxNTBaFw0yMjAzMDMxOTQxNTBaMHAxCzAJBgNVBAYTAk5a\n' +
                    'MSMwIQYDVQQDDBpGSURPIENvbmZvcm1hY2UgVGVzdCBUb29sczEWMBQGA1UECgwN\n' +
                    'RklETyBBbGxpYW5jZTEkMCIGA1UECwwbQ2VydGlmaWNhdGlvbiBXb3JraW5nIEdy\n' +
                    'b3VwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2tT2T6XmG8p5jW90\n' +
                    'KSFFR2sRzNJcAV135eFkio/PYvNROhJWjb2lfrpveu2lLdCqFPhCZShl4gkhsUmF\n' +
                    'uO8liYrWuR3/q3plLg5XevSgqtcbiNUBFEdtcC8T+mqpakcV9u2CvxYGYvAhWE4A\n' +
                    'CNc8bALzFjEq3wIGQTvlA3/T97gSLGoUzAvZN1941vSgG/kZ/RNuU2cU7n7pJzxj\n' +
                    'yOL8aG/iBd2ZKj+vmkOyvpXIeg51xOw2q4nfOkE3kNI09o1VhY1/9VgUPOZPJs6a\n' +
                    'BiMigZiH7iasAXA/fl5OjCjOMfh6S+328jw9kw9x687wvTIoujxhwBAA1LboeUZZ\n' +
                    '048DSwIDAQABox0wGzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIGwDANBgkqhkiG\n' +
                    '9w0BAQsFAAOCAQEAsPm60cQPtjOWGy+3J0PEj6MaRNqwYIh4IW4+ABb1yuepTQzF\n' +
                    '3/DFT56nMPjKy+G8ozbb4HUeM4HsqYZTNGgqB7mpOjfnSL2E5Yo2gw4ITiaB4jWo\n' +
                    'oeV/0KZMTd2rrr1ftnLbz2Maub4j0XuNQIsWMTbscuHu8DAaIEY34Klgb4LrOoHh\n' +
                    'KWeW3Kf/kMqpwum1pwd64NLj3WSE5WFrsl5dwVj374pYeQ5AdzCmDDuevhu5dcfP\n' +
                    'BnLe7WjPFoYsbiuh+F/YGbZx8olL8SvP/l/9DYNM9A0v9nV69nrm7zcQKm1eGc15\n' +
                    'z0yzKOiwVdwtYWBDjygxHlLpPFZxD/Hzvmp/FA==\n' +
                    '-----END CERTIFICATE-----',
            'privKey': '-----BEGIN PRIVATE KEY-----\n' + 
                    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDa1PZPpeYbynmN\n' + 
                    'b3QpIUVHaxHM0lwBXXfl4WSKj89i81E6ElaNvaV+um967aUt0KoU+EJlKGXiCSGx\n' + 
                    'SYW47yWJita5Hf+remUuDld69KCq1xuI1QEUR21wLxP6aqlqRxX27YK/FgZi8CFY\n' + 
                    'TgAI1zxsAvMWMSrfAgZBO+UDf9P3uBIsahTMC9k3X3jW9KAb+Rn9E25TZxTufukn\n' + 
                    'PGPI4vxob+IF3ZkqP6+aQ7K+lch6DnXE7Darid86QTeQ0jT2jVWFjX/1WBQ85k8m\n' + 
                    'zpoGIyKBmIfuJqwBcD9+Xk6MKM4x+HpL7fbyPD2TD3HrzvC9Mii6PGHAEADUtuh5\n' + 
                    'RlnTjwNLAgMBAAECggEAQ5sdiZfQUm+oQ+jV80sDE0Bh3Gx03jsZKp0KqcAqKwDO\n' + 
                    '7Gjz8pBPi6pffJPkvxXDJf1YzdXAPCfkD9iOBodjim2pTsGU1k5W6famUic3Z/BS\n' + 
                    '4mAkGDbE+a6htnCzbFEP2RyhkxVj3bcgJh7a5eBRG3GB1i5Ud1cxxX+SjhU00Ees\n' + 
                    'ZPbxoWz92oWhFKHaLZzuQBVJMarh7BEvO46LwmBlRacBxGzMtMVyM+OWyD9xhB5u\n' + 
                    'GJ8G44mrC2lyTYv8/3ypvd5FJjx4OzwOUvqbama2rzMK5Szx2zOjBeZLtklyGEsA\n' + 
                    '7wzZUx8pwBcJQbTfXmGeJ3fn5gEsSyWU7t53k84YcQKBgQD6Lga1UQNOmOpiyJsk\n' + 
                    '55U4wbdpEfcAkMUZXgM8LJaAF4MOinamtZNS0+FSDj1VIaT/fg9VSRxcN5J6Y2Y7\n' + 
                    'PPhpAeKbcyqs1X6QgNACAJ1spQtl/g2V1cpmnazKjS5MqKPZQhcdrLk2q/ARfy0r\n' + 
                    'HgXGt3hvlSOkC9oVwMsF/wNIyQKBgQDf7D1vFBRL9lN1YypSddVVtPLVNaccW4/4\n' + 
                    'KT5Scuna+uFT2X2Qtiqfy7XBYOBGFf6X7yAm4W2eQcgk4eI9OXQIyrnP58AN03S5\n' + 
                    'DzRwYgxhAn+6mNHM2NMLzOOdjfQDzy/E9XxDcTpjwYw5IWl7CFHddtkLPdZr7YtB\n' + 
                    's9/T6LRJcwKBgHqGyjBJEgaPa9OfjiQ/61xVu58Q9ljnjjCDU7BH4hmv6jbX5450\n' + 
                    'RUf+j07hvHYSOT4MHjRVzzb23J1mSy5eCQdcrgAWImNtWEQrYjRo2rDYEEIOb9bf\n' + 
                    'UvZ46KR3CqLuwPhpnuqgqkE1aikXkSaZ2JhfSPPVJhR03YVj28r+/zvJAoGBALhX\n' + 
                    '4yeMDz2OF50fO1tReISrh/JwzhdxZa+2PIFh6xYEzfXaqh21apfM+9+sYlYwiz0H\n' + 
                    'dp+rnDPaEewTLc6beuQ2CQyYzKpVN9WWJ+SRQ4GlrgOvBaEvq2cekRBHKejs63Wp\n' + 
                    'Z1iaYah4UXlDAXRxH/xDeGFh0iFeGPPJIm5xN+LzAoGAP1PZ35gPEJ4DrpM8pZMh\n' + 
                    '1sGMINYM7y2nnQd4oMUxZsA9+Yp741Ik8GLGfUtAnKirmjIiTsn1I/4AAsNQZ+mm\n' + 
                    'gov/JCDmQyGGpug0SdEL2wTvUh8q8lNm3iwuCsrl0t8598GbkT0jKpHsrcVJN4kC\n' + 
                    'w3pgdgGXh/qIy0U4Q2Dbhyg=\n' + 
                    '-----END PRIVATE KEY-----',
            'pubKey': '-----BEGIN PUBLIC KEY-----\n' +
                    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2tT2T6XmG8p5jW90KSFF\n' +
                    'R2sRzNJcAV135eFkio/PYvNROhJWjb2lfrpveu2lLdCqFPhCZShl4gkhsUmFuO8l\n' +
                    'iYrWuR3/q3plLg5XevSgqtcbiNUBFEdtcC8T+mqpakcV9u2CvxYGYvAhWE4ACNc8\n' +
                    'bALzFjEq3wIGQTvlA3/T97gSLGoUzAvZN1941vSgG/kZ/RNuU2cU7n7pJzxjyOL8\n' +
                    'aG/iBd2ZKj+vmkOyvpXIeg51xOw2q4nfOkE3kNI09o1VhY1/9VgUPOZPJs6aBiMi\n' +
                    'gZiH7iasAXA/fl5OjCjOMfh6S+328jw9kw9x687wvTIoujxhwBAA1LboeUZZ048D\n' +
                    'SwIDAQAB\n' +
                    '-----END PUBLIC KEY-----'
        },
        'SECP256R1': {
            'cert': '-----BEGIN CERTIFICATE-----\n'+
                    'MIIB7DCCAZKgAwIBAgIBBDAKBggqhkjOPQQDAjBwMQswCQYDVQQGEwJOWjEjMCEG\n' +
                    'A1UEAwwaRklETyBDb25mb3JtYWNlIFRlc3QgVG9vbHMxFjAUBgNVBAoMDUZJRE8g\n' +
                    'QWxsaWFuY2UxJDAiBgNVBAsMG0NlcnRpZmljYXRpb24gV29ya2luZyBHcm91cDAe\n' +
                    'Fw0xNzAyMjkxNDMxMTJaFw0yMjAyMjgxNDMxMTJaMHAxCzAJBgNVBAYTAk5aMSMw\n' +
                    'IQYDVQQDDBpGSURPIENvbmZvcm1hY2UgVGVzdCBUb29sczEWMBQGA1UECgwNRklE\n' +
                    'TyBBbGxpYW5jZTEkMCIGA1UECwwbQ2VydGlmaWNhdGlvbiBXb3JraW5nIEdyb3Vw\n' +
                    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZaRKB92Abz8nqEZFf8Xz84ajfA7l\n' +
                    'Ljt4O+i2wq1FnD/svIyTyEYm/QbOYJC0GUVE+L6V7OiD8K9Z4PfiBFRO+qMdMBsw\n' +
                    'DAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCBsAwCgYIKoZIzj0EAwIDSAAwRQIgWDy1\n' +
                    'Oxu8PT6diGXycY0rxb1e16omexfQ+Iv9KOg5p9cCIQCFPPCArmDh3+EyxI/OaZFP\n' +
                    'vW2kG2hQBmi9PnC+bBrfYQ==\n' +
                    '-----END CERTIFICATE-----',
            'privKey': '-----BEGIN PRIVATE KEY-----\n' + 
                    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/+b3Id6goKQJ9IkZ\n' + 
                    'JlPH1mbrsZhBFly8ZWpctt+qpTehRANCAARlpEoH3YBvPyeoRkV/xfPzhqN8DuUu\n' + 
                    'O3g76LbCrUWcP+y8jJPIRib9Bs5gkLQZRUT4vpXs6IPwr1ng9+IEVE76\n' + 
                    '-----END PRIVATE KEY-----',
            'pubKey': '-----BEGIN PUBLIC KEY-----\n' +
                    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZaRKB92Abz8nqEZFf8Xz84ajfA7l\n' +
                    'Ljt4O+i2wq1FnD/svIyTyEYm/QbOYJC0GUVE+L6V7OiD8K9Z4PfiBFRO+g==\n' +
                    '-----END PUBLIC KEY-----'
        },
        'SECP256K1': {
            'cert': '-----BEGIN CERTIFICATE-----\n' + 
                    'MIIB6jCCAY+gAwIBAgIBBDAKBggqhkjOPQQDAjBwMQswCQYDVQQGEwJOWjEjMCEG\n' + 
                    'A1UEAwwaRklETyBDb25mb3JtYWNlIFRlc3QgVG9vbHMxFjAUBgNVBAoMDUZJRE8g\n' + 
                    'QWxsaWFuY2UxJDAiBgNVBAsMG0NlcnRpZmljYXRpb24gV29ya2luZyBHcm91cDAe\n' + 
                    'Fw0xNzAzMDQyMzI4MDhaFw0yMjAzMDMyMzI4MDhaMHAxCzAJBgNVBAYTAk5aMSMw\n' + 
                    'IQYDVQQDDBpGSURPIENvbmZvcm1hY2UgVGVzdCBUb29sczEWMBQGA1UECgwNRklE\n' + 
                    'TyBBbGxpYW5jZTEkMCIGA1UECwwbQ2VydGlmaWNhdGlvbiBXb3JraW5nIEdyb3Vw\n' + 
                    'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE0Oer7PXYhFqqxl9Dx7sF6arkk5BGY4qo\n' + 
                    'hviYXz//W+GMyUe97evO4e9O5HpjVwjL1wJt/8+u2LLN+Ul959rtnKMdMBswDAYD\n' + 
                    'VR0TBAUwAwEB/zALBgNVHQ8EBAMCBsAwCgYIKoZIzj0EAwIDSQAwRgIhAJ47vMX6\n' + 
                    'GfrlVCbi+Yvv8IXudZWWlhtm/pOaIKmFsoWjAiEAger2aGXFKXG/dARiNIkKHI48\n' + 
                    '/lxCBmYY6MhXcYjqaTw=\n' + 
                    '-----END CERTIFICATE-----',
            'privKey': '-----BEGIN PRIVATE KEY-----\n' +
                    'MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgJKiMMOOe2InCy3wIwc8P\n' +
                    'TR3mZIpg/IcGTywsXiZy2KuhRANCAATQ56vs9diEWqrGX0PHuwXpquSTkEZjiqiG\n' +
                    '+JhfP/9b4YzJR73t687h707kemNXCMvXAm3/z67Yss35SX3n2u2c\n' +
                    '-----END PRIVATE KEY-----',

            'pubKey': '-----BEGIN PUBLIC KEY-----\n' +
                    'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE0Oer7PXYhFqqxl9Dx7sF6arkk5BGY4qo\n' +
                    'hviYXz//W+GMyUe97evO4e9O5HpjVwjL1wJt/8+u2LLN+Ul959rtnA==\n' +
                    '-----END PUBLIC KEY-----'
        }
    }
/* ----- BATCH CERT AND KEYPAIR ENDS----- */

    /* ---------- HELPERS ---------- */
        let DERTLV = new TLV({
            'TagFieldSize' : 1,
            'LengthFieldSize' : 1,
            'TagDirectory': TAG_ASN1_DER
        })

        /**
         * Returns true if given keyObject is of Elliptic Curve type.
         * @param  {Object} key - key object
         * @return {Boolean}    - is EC type
         */
        let isECKey = (key) => !!key.curveName

        /**
         * Takes any DER integer and ensures that its positive
         * @param  {Buffer} numberBuffer
         * @return {Buffer}
         */
        let enforceDERPositiveInt = (numberBuffer) => {
            if(!!(numberBuffer[0] & 0x80))
                return mergeArrayBuffers(new Uint8Array([0x00]), numberBuffer);

            return numberBuffer
        }

        /**
         * Returns EC publicKey in RAW and DER formats
         * @param  {Object} pubKey - EC publicKey
         * @return {Object}        - public key export method object
         */
        let exportECCX962PubKey = (pubKey) => {

            if(!pubKey.curveName)
                throw new TypeError(`public key is not an EC key!`)

            return {
                /**
                 * Returns DER encoded X962 EC public key:
                 * ALG_KEY_ECC_X962_DER 0x101
                        DER [ITU-X690-2008] encoded ANSI X.9.62 formatted SubjectPublicKeyInfo
                        [RFC5480] specifying an elliptic curve public key.

                        I.e. a DER encoded SubjectPublicKeyInfo as defined in [RFC5480].

                        Authenticator implementations must generate namedCurve in the ECParameters
                        object which is included in the AlgorithmIdentifier. A FIDO UAF Server must
                        accept namedCurve in the ECParameters object which is included in the
                        AlgorithmIdentifier.

                 * @return {ArrayBuffer} - Public Key Array Buffer
                 */
                'getDER': () => {
                    let curves = {
                        /* http://www.alvestrand.no/objectid/1.3.132.0.10.html */
                        'secp256k1': '1.3.132.0.10',
                        /* http://www.alvestrand.no/objectid/1.2.840.10045.3.1.7.html */
                        'secp256r1': '1.2.840.10045.3.1.7'
                    }

                    let namedCurve = curves[pubKey.curveName];

                    if(!namedCurve)
                        throw new Error(`Curve ${pubKey.curveName} is not supported!`)

                    let algorithmOID = new jsrsasign.KJUR.asn1.DERObjectIdentifier({
                        'oid': '1.2.840.10045.2.1' // ECDSA and ECDH Public Key.
                    })

                    let namedCurveOID = new jsrsasign.KJUR.asn1.DERObjectIdentifier({
                        'oid': namedCurve
                    })

                    let OIDSeq = new jsrsasign.KJUR.asn1.DERSequence();
                    OIDSeq.appendASN1Object(algorithmOID);
                    OIDSeq.appendASN1Object(namedCurveOID);

                    let SubjectPublicKey = new jsrsasign.KJUR.asn1.DERBitString();
                    SubjectPublicKey.setHexValueIncludingUnusedBits('00' + pubKey.pubKeyHex);

                    let SubjectPublicKeyInfoSeq = new jsrsasign.KJUR.asn1.DERSequence();
                    SubjectPublicKeyInfoSeq.appendASN1Object(OIDSeq);
                    SubjectPublicKeyInfoSeq.appendASN1Object(SubjectPublicKey);

                    let SubjectPublicKeyInfoSeqHex = SubjectPublicKeyInfoSeq.getEncodedHex();

                    return hex.decode(SubjectPublicKeyInfoSeqHex)
                },

                /**
                 * Returns RAW encoded X962 EC public key:
                 * ALG_KEY_ECC_X962_RAW 0x100
                        Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
                        I.e. [0x04, X (32 bytes), Y (32 bytes)] . Where the byte 0x04 denotes the
                        uncompressed point compression method.

                 * @return {ArrayBuffer} - Public Key Array Buffer
                 */
                'getRAW': () => {
                    let XYHexPair = pubKey.getPublicKeyXYHex();
                    let xBuffer   = hex.decode(XYHexPair.x);
                    let yBuffer   = hex.decode(XYHexPair.y);
                    let PCM       = new Uint8Array([0x04]);

                    return mergeArrayBuffers(PCM, xBuffer, yBuffer)
                }
            }
        }

        /**
         * Returns RSAPSS publicKey in RAW and DER formats
         * @param  {Object} pubKey - EC publicKey
         * @return {Object}        - public key export method object
         */
        let exportRSA2048PSSPubKey = (pubKey) => {

            if(pubKey.curveName)
                throw new TypeError(`public key is not an RSA key!`)

            return {
                /**
                 * Returns DER encoded RSAPSS public key:
                 * ALG_KEY_RSA_2048_PSS_DER 0x103
                    ASN.1 DER [ITU-X690-2008] encoded RSASSA-PSS [RFC3447] public key [RFC4055].
                    The default parameters according to [RFC4055] must be assumed, i.e.
                        Mask Generation Algorithm MGF1 with SHA256
                        Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
                        Trailer Field value of 1, which represents the trailer field with hexadecimal
                        value 0xBC.
                    That is, a DER encoded SEQUENCE { n INTEGER, e INTEGER }.


                 * @return {ArrayBuffer} - Public Key Array Buffer
                 */
                'getDER': () => {
                    let nDERInteger = new jsrsasign.KJUR.asn1.DERInteger();
                    nDERInteger.setByBigInteger(pubKey.n);

                    let eDERInteger = new jsrsasign.KJUR.asn1.DERInteger();
                    eDERInteger.setByInteger(pubKey.e);

                    let DERSeq = new jsrsasign.KJUR.asn1.DERSequence();
                    DERSeq.appendASN1Object(nDERInteger);
                    DERSeq.appendASN1Object(eDERInteger);

                    let DERSeqHex = DERSeq.getEncodedHex();

                    return hex.decode(DERSeqHex)
                },
                /**
                 * Returns RAW encoded RSAPSS public key:
                 * ALG_KEY_RSA_2048_PSS_RAW 0x102
                        Raw encoded RSASSA-PSS public key [RFC3447].
                        The default parameters according to [RFC4055] must be assumed, i.e.
                            Mask Generation Algorithm MGF1 with SHA256
                            Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
                            Trailer Field value of 1, which represents the trailer field with hexadecimal
                            value 0xBC.
                        That is, [n (256 bytes), e (N-n bytes)] . Where N is the total length of the field.
                        This total length should be taken from the object containing this key, e.g. the TLV
                        encoded field.

                 * @return {ArrayBuffer} - Public Key Array Buffer
                 */
                'getRAW': () => {
                    /**
                     * Removes 00 byte padding from the public key
                     * @param  {Array} byteArray - array of intergers
                     * @return {Array}           - fixed array
                     */
                    let fixByteArray = (byteArray) => {
                        if(byteArray.length > 256)
                            return byteArray.splice(1, byteArray.length - 1)

                        return byteArray
                    }

                    let nBuffer = new Uint8Array(fixByteArray(pubKey.n.toByteArray()));
                    let eBuffer = numberToArrayBuffer(pubKey.e);

                    return mergeArrayBuffers(nBuffer, eBuffer)
                }
            }
        }

        /**
         * Generates ECDSA signature of a given message
         * @param  {ArrayBuffer} message - message array buffer
         * @param  {Object} privateKey   - EC private key
         * @param  {String} exportType   - der or raw
         * @return {Object}              - signature method object
         */
        let signECDSA = (message, privateKey, exportType) => {
            return new Promise((resolve, reject) => {
                if(!isECKey(privateKey))
                    throw new TypeError(`private key is not an EC key!`)

                if(!message || type(message) !== 'ArrayBuffer' && type(message.buffer) !== 'ArrayBuffer')
                    throw new TypeError('message is missing, or it\'s not an ArrayBuffer!')

                if(!exportType || ( exportType !== 'der' && exportType !== 'raw' ))
                    throw new TypeError('exportType is undefined or it\'s value is not "ber" or "raw"')

                let signature = new jsrsasign.KJUR.crypto.Signature({"alg": "SHA256withECDSA"});
                signature.init(privateKey);

                let bufferHEX = hex.encode(message);
                signature.updateHex(bufferHEX)

                let signHex = signature.sign();

                let removeZeroByte = (buffer) => {
                    if(buffer.byteLength > 32)
                        return buffer.slice(1, buffer.length)

                    return buffer
                }

                let derASNBuffer  = hex.decode(signHex);
                let derASNDecoded = DERTLV.parser.parseButSkipValueDecoding(derASNBuffer);
                let R = removeZeroByte(derASNDecoded['SEQUENCE']['INTEGER'][0]);
                let S = removeZeroByte(derASNDecoded['SEQUENCE']['INTEGER'][1]);

                if(exportType === 'der') {
                    /**
                     * Returns ECDSA signature based on given key for:
                     * 
                     * OR ALG_SIGN_SECP256R1_ECDSA_SHA256_DER 0x02
                            DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the NIST secp256r1 curve.
                            I.e. a DER encoded SEQUENCE { r INTEGER, s INTEGER }

                     * OR ALG_SIGN_SECP256K1_ECDSA_SHA256_DER 0x06
                            DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the secp256k1 curve.
                            I.e. a DER encoded SEQUENCE { r INTEGER, s INTEGER }
                     */
                    let DERSeq  = new jsrsasign.KJUR.asn1.DERSequence();
                    let DerIntR = new jsrsasign.KJUR.asn1.DERInteger({'hex': hex.encode(enforceDERPositiveInt(R))});
                    let DerIntS = new jsrsasign.KJUR.asn1.DERInteger({'hex': hex.encode(enforceDERPositiveInt(S))});

                    DERSeq.appendASN1Object(DerIntR);
                    DERSeq.appendASN1Object(DerIntS);

                    let DERSeqHex = DERSeq.getEncodedHex();

                    resolve(hex.decode(DERSeqHex));
                } else {
                    /**
                     * Returns ECDSA signature based on given key for:
                     * 
                     * OR ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW 0x01
                            An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
                            I.e. [R (32 bytes), S (32 bytes)]

                     * OR ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW 0x05
                            An ECDSA signature on the secp256k1 curve which must have raw R and S buffers, encoded in big-endian order.
                            I.e.[R (32 bytes), S (32 bytes)]

                     * @return {ArrayBuffer} - Signature Array Buffer
                     */
                    
                    resolve(mergeArrayBuffers(R, S))
                }
            })
        }

        /**
         * Generates RSA PSS signature of a given message
         * @param  {ArrayBuffer} message - message array buffer
         * @param  {Object} privateKey   - RSA   private key
         * @param  {String} exportType   - der or raw
         * @return {Object}              - signature method object
         */
        let signRSAPSS = (message, privateKey, exportType) => {

            if(isECKey(privateKey))
                throw new TypeError(`private key is not RSA key!`)

            if(!message || type(message) !== 'ArrayBuffer' && type(message.buffer) !== 'ArrayBuffer')
                throw new TypeError('message is missing, or it\'s not an ArrayBuffer!')

            if(!exportType || ( exportType !== 'der' && exportType !== 'raw' ))
                throw new TypeError('exportType is undefined or it\'s value is not "ber" or "raw"')


            let privateKeyJWK = jsrsasign.KEYUTIL.getJWKFromKey(privateKey)

            return window.crypto.subtle.importKey(
                'jwk',
                privateKeyJWK,
                {
                    'name': 'RSA-PSS',
                    'hash': {
                        'name': 'SHA-256'
                    }
                },
                false,
                ['sign']
            )
                .then((key) => {
                    return window.crypto.subtle.sign(
                        {
                            'name': 'RSA-PSS',
                            'saltLength': 32
                        },
                        key,
                        message
                    )
                })
                .then((signature) => {
                    /**
                     * Returns RSA signature for:
                     * ALG_SIGN_RSASSA_PSS_SHA256_DER 0x04
                            DER [ITU-X690-2008] encoded OCTET STRING (not BIT STRING!) containing
                            the RSASSA-PSS [RFC3447] signature [RFC4055] [RFC4056]. The default
                            parameters as specified in [RFC4055]
                            must be assumed, i.e.
                                Mask Generation Algorithm MGF1 with SHA256
                                Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
                                Trailer Field value of 1, which represents the trailer field with hexadecimal
                                value 0xBC.
                            I.e. a DER encoded OCTET STRING (including its tag and length bytes).


                     * @return {ArrayBuffer} - Signature Array Buffer
                     */
                    if(exportType === 'der') {
                        let derOSE = new jsrsasign.KJUR.asn1.DEROctetString({
                            'hex': hex.encode(signature)
                        });

                        return hex.decode(derOSE.getEncodedHex())
                        
                    } else {
                        /**
                         * Returns RSA signature for:
                         * ALG_SIGN_RSASSA_PSS_SHA256_RAW 0x03
                                RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in bigendian
                                order [RFC4055] [RFC4056]. The default parameters as specified in
                                [RFC4055] must be assumed, i.e.
                                    Mask Generation Algorithm MGF1 with SHA256
                                    Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
                                    Trailer Field value of 1, which represents the trailer field with hexadecimal
                                    value 0xBC.
                                I.e. [ S (256 bytes) ]

                         * @return {ArrayBuffer} - Signature Array Buffer
                         */
                        return signature
                    }
                    
                })
        }

        /**
         * Imports Certificate and keys
         * @return {Object} - certificate and key pair object
         */
        let getCertificateObject = (signatureAlgorithm) => {
            let certificateObject
            if(signatureAlgorithm.indexOf('RSA') !== -1)
                certificateObject = certs['RSA'];
            else
                if(signatureAlgorithm.indexOf('SECP256R1') !== -1)
                    certificateObject = certs['SECP256R1'];
                else
                    certificateObject = certs['SECP256K1'];

            let certificate = new jsrsasign.X509();
            certificate.readCertPEM(certificateObject.cert);

            return {
                'cert': hex.decode(certificate.hex),
                'pubKey': jsrsasign.KEYUTIL.getKey(certificateObject.pubKey),
                'privKey': jsrsasign.KEYUTIL.getKey(certificateObject.privKey)
            }
        }
    /* ---------- HELPERS END ---------- */

    let KeyEnclave = function(params, modifierParams) {
        let storage = {};
        let signatureAlgorithm  = signatureAlgorithms[params.authenticationAlgorithm];
        let publicKeyAlgorithm  = publicKeyAlgorithms[params.publicKeyAlgAndEncoding];
        let batchCertificate    = getCertificateObject(params.authenticationAlgorithm);

        let PersonaID    = 'environmentMagicID';
        let ASMToken     = generateRandomString();
        let CallerID     = 'JS.Function';
        let hashFunction = 'SHA-256';


        return {
            /**
             * Returns promise to sign message
             * @param  {ArrayBuffer} message  - ArrayBuffer of message to sign
             * @param  {keyObject} privateKey - JSRSASIGN Key Object
             * @return {Promise}
             */
            'signMessage': (message, privateKey) => {
                if(isECKey(privateKey))
                    return signECDSA(message, privateKey, signatureAlgorithm.export)
                else
                    return signRSAPSS(message, privateKey, signatureAlgorithm.export)
            },

            /**
             * Generates a signature of the given message using batch private key
             * @param  {ArrayBuffer} - message
             * @return {Promise}
             */
            'signWithBatchPrivateKey': function(message) {
                return this.signMessage(message, batchCertificate.privKey)
            },

            /**
             * Generates a signature of the given message using batch private key
             * @param  {String} KHAccessToken - KHAccessToken
             * @param  {String} keyID         - keyID/KeyHandle
             * @param  {ArrayBuffer} message  - message to sign
             * @return {Promise}
             */
            'signData': function(KHAccessToken, keyID, message) {
                let keyObject  = storage[keyID];
                let privateKey = keyObject.privKey;

                if(!keyObject || keyObject.KHAccessToken !== KHAccessToken)
                    return ErrorPromise('UAF_CMD_STATUS_ACCESS_DENIED');

                return this.signMessage(message, privateKey)
            },


            /**
             * Generates new unique key pair
             * @param  {String} KHAccessToken - Base64URL encoded KHAccessToken
             * @param  {String} username      - username
             * @return {Promise}
             */
            'generateNewKeyPair': (KHAccessToken, username) => {
                let keyGenParams = signatureAlgorithm.keyGeneration;
                return new Promise((resolve, reject) => {
                    /**
                     * Replacing JSRSASIGN RSA key generation with webcrypto api
                     * WAYYYYYYYYYYYYYYY Faster
                     */
                    if(keyGenParams.type === 'RSA') {
                        window.crypto.subtle.generateKey(
                            {
                                'name': 'RSA-PSS',
                                'modulusLength': 2048, //can be 1024, 2048, or 4096
                                'publicExponent': new Uint8Array([0x01, 0x00, 0x01]),
                                'hash': {
                                    'name': 'SHA-256'
                                },
                            },
                            true,
                            ['sign', 'verify']
                        )
                        .then((keyPair) => {
                            return Promise.all([
                                window.crypto.subtle.exportKey('jwk', keyPair.publicKey),
                                window.crypto.subtle.exportKey('jwk', keyPair.privateKey)
                            ])
                        })
                        .then((keyPair) => {
                            let privateKey = jsrsasign.KEYUTIL.getKey(keyPair[1])
                            let publicKey  = jsrsasign.KEYUTIL.getKey(keyPair[0])

                            resolve({
                                'pubKeyObj': publicKey,
                                'prvKeyObj': privateKey
                            })
                        })
                        .catch((err) => {
                            reject(err)
                        })
                    } else { 
                        let newKeyPair = jsrsasign.KEYUTIL.generateKeypair(keyGenParams.type, keyGenParams.param);
                        resolve(newKeyPair)
                    }
                })
                .then((newKeyPair) => {
                    if(modifierParams && modifierParams.reuseKeyPair && Object.keys(storage).length) {
                        /**
                         * Returning keyID of the first key
                         */
                        return base64url.decode(Object.keys(storage)[0])
                    } else {
                        /* Generating new keyID */
                        let keyIDBuffer = new Uint8Array(32);
                        window.crypto.getRandomValues(keyIDBuffer);
                        let keyID = base64url.encode(keyIDBuffer);

                        /* Saving keypair */
                        storage[keyID] = {
                            'KHAccessToken': KHAccessToken,
                            'timestamp': new Date().getTime(),
                            'pubKey'   : newKeyPair.pubKeyObj,
                            'privKey'  : newKeyPair.prvKeyObj,
                            'username' : username,
                        }

                        return keyIDBuffer.buffer
                    }
                })
            },

            /**
             * Exports public key defined by keyID
             * @param  {arrayBuffer} keyIDBuffer - keyID in array buffer fprmat
             * @return {Promise}
             */
            'exportPublicKey': (keyIDBuffer) => {
                let keyID = base64url.encode(keyIDBuffer)

                return new Promise((resolve, reject) => {
                    if(!storage[keyID])
                        reject(`No keypair registered with KeyId: ${keyID}!`)

                    resolve(storage[keyID].pubKey)
                })
                .then((pubKey) => {
                    let keyExportObject;

                    /**
                     * if key is EC or RSA
                     */
                    if(isECKey(pubKey))
                        keyExportObject = exportECCX962PubKey(pubKey);
                    else
                        keyExportObject = exportRSA2048PSSPubKey(pubKey);

                    if(publicKeyAlgorithm.export === 'der')
                        return keyExportObject.getDER()
                    else
                        return keyExportObject.getRAW()

                })
            },

            /**
             * Retrieves batch certificate
             * @return {Promise}
             */
            'getBatchCertificate': () => {
                return new Promise((resolve) => {
                    resolve(batchCertificate.cert)
                })
            },

            /**
             * Get list of users
             * @return {Object} - list of users and keyIDs
             */
            'getUsers': function(appID) {
                let keyIDUniqueID = breakURL(appID).host;
                return this.generateKHAccessToken(appID)
                    .then((KHAccessTokenBuffer) => base64url.encode(KHAccessTokenBuffer))
                    .then((KHAccessToken) => {
                        let users = [];

                        for(let keyID in storage) {
                            // if(storage[keyID].KHAccessToken == KHAccessToken) {
                                users.push({
                                    'keyID': keyID,
                                    'username': storage[keyID].username,
                                    'timestamp': storage[keyID].timestamp
                                })
                            // }
                        }

                        if(!users.length)
                            throw new Error('UAF_ASM_STATUS_ACCESS_DENIED');

                        return users;
                    })
            },

            /**
             * Checks if KeyID exists
             * @param  {String} keyID
             * @param  {String} KHAccessToken
             * @return {Promise}
             */
            'keyIDExists': (keyID) => {
                if(storage[keyID])
                    return true

                return false
            },

            /**
             * Returns promise to delete KeyHandle specified by keyID and KHAccessToken
             * @param  {String} keyID
             * @param  {String} KHAccessToken
             * @return {Promise}
             */
            'removeKeyID': (keyID, KHAccessToken) => {
                return new Promise((resolve, reject) => {
                    /**
                     * As defined by UAF Authenticator Commands v1.0 - 6.2.2.4
                     */
                    if(storage[keyID]) {
                        if(storage[keyID].KHAccessToken == KHAccessToken) {
                            delete storage[keyID]
                            resolve()
                        } else
                            reject(new Error('UAF_CMD_STATUS_ACCESS_DENIED'))
                    } else {
                        resolve()
                    }
                })
            },

            /**
             * Generates KHAccessToken based on the given appID
             * @param {String} appID - Application ID
             * @return {Promise}
             */
            'generateKHAccessToken': (appID) => {
                if(!appID)
                    return ErrorPromise('AppID is undefined!');

                let keyIDUniqueID = breakURL(appID).host;
                let KHAccessTokenString = keyIDUniqueID + ASMToken + PersonaID + CallerID;
                let KHAccessTokenArrayBuffer = stringToArrayBuffer(KHAccessTokenString);

                return crypto.subtle
                    .digest(hashFunction, KHAccessTokenArrayBuffer)
            },

            /**
             * Returns hash of a provided data 
             * @param  {ArrayBuffer} dataBuffer - data
             * @return {Promise}
             */
            'hash': (dataBuffer) => {
                return crypto.subtle
                    .digest(hashFunction, dataBuffer)
            },

            /**
             * Generates array buffer filled with secure random bytes.
             * @param  {Integer} len - length of buffer
             * @return {ArrayBuffer}   - random buffer
             */
            'randomBuffer': (len) => {
                if(!len || type(len) !== 'Number')
                    throw new Error('No length of random buffer was specified!')

                let buffer = new Uint8Array(len);
                window.crypto.getRandomValues(buffer);

                return buffer.buffer
            }
        }
    }

    window.UAF.KeyEnclave = KeyEnclave;

})()
