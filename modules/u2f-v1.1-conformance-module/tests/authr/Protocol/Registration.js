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

describe(`

        U2F-Register-1

        Test authenticator process Register command

    `, function() {



    let deviceInfo = undefined;
    let metadata = window.config.test.metadataStatement;
    before(() => {
        deviceInfo = getDeviceInfo();

        if (!deviceInfo)
            throw new Error('No U2F devices presented!')
    });

    this.timeout(10000);
    this.retries(3);

/* ---------- Positive Tests ---------- */
    it(`P-1

        Send a valid APDU Register command, wait for response and check that:
            (a) response status is SW_NO_ERROR
            (b) parse response data and:
                (i)   check that reserve byte(data[1]) is equal to 0x05
                (ii)  extract an attestation certificate, and signature
                (iii) construct original challenge data, and verify signature

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {
                assert.equal(APDU_STATUS_CODES.SW_NO_ERROR, result.statusCode, 'Authenticator returned an error: ' + result.statusCode);
                
                assert.equal(0x05, result.responseStruct.RESERVE, 'Reserve byte MUST be set to 0x05!');
                assert.isTrue(verifyRegistrationResponse(challengeHash, appIDHash, result.responseStruct), 'Failed to verify Registration signature!');
            })
    })

    it(`P-2

        Send a valid APDU Register command, wait for response, extract attestation certificate, compute Subject Key Identifier as defined in RFC5280 section 4.2.1.2, and check that metadata contains the computed SKID

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {
                assert.equal(APDU_STATUS_CODES.SW_NO_ERROR, result.statusCode, 'Authenticator returned an error: ' + result.statusCode);

                let skid = calculateSubjectKeyIdentifier(result.responseStruct.CERT);

                assert.isDefined(metadata.attestationCertificateKeyIdentifiers, 'Metadata is missing "attestationCertificateKeyIdentifiers" field!');
                assert.isArray(metadata.attestationCertificateKeyIdentifiers, 'Metadata.attestationCertificateKeyIdentifiers MUST be of type SEQUENCE!');
                assert.isNotEmpty(metadata.attestationCertificateKeyIdentifiers, 'Metadata.attestationCertificateKeyIdentifiers can not be empty!');
                assert.include(metadata.attestationCertificateKeyIdentifiers, skid, `Expected Metadata.attestationCertificateKeyIdentifiers to include Subject Key Identifier of "${skid}"!`);
            })
    })

    it(`P-3

        Send a valid APDU Register command, wait for response, extract attestation certificate, and try verifying it against the attestation roots in the metadata.attestationRootCertificates

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(32);

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendValidCTAP_MSG(U2F_INS_REGISTER, payload)
            .then((result) => {
                assert.equal(APDU_STATUS_CODES.SW_NO_ERROR, result.statusCode, 'Authenticator returned an error: ' + result.statusCode);

                let batchCertificateBase64 = base64.encode(result.responseStruct.CERT);

                let passed = false;
                for(let attestationRootBase64 of metadata.attestationRootCertificates) {
                    let certificatePath    = [batchCertificateBase64, attestationRootBase64];
                    let certificatePathPEM = certificatePath.map((certificateBase64) => base64StringCertToPEM(certificateBase64));

                    if(verifyCertificateChain(certificatePathPEM)) {
                        passed = true;
                        break
                    }
                }

                assert.isTrue(passed, 'Could not verify certitificate path!');
            })
    })

/* ---------- Negative Tests ---------- */
     it(`F-1

        Send an APDU Register command with a data buffer size of less than 64 bytes, and check that response status code is SW_WRONG_LENGTH. Register expects 64 bytes buffer.

    `, () => {
        let challengeHash = generateRandomBuffer(32);
        let appIDHash     = generateRandomBuffer(generateSecureRandomInt(1, 31)); // small hash

        let payload = generateAPDURegisterFrame(challengeHash, appIDHash);

        return sendCTAP_MSG(U2F_INS_REGISTER, payload)
            .catch((result) => {
                assert.equal(APDU_STATUS_CODES.SW_WRONG_LENGTH, result.statusCode, `Expected error code SW_WRONG_LENGTH. Received ${APDU_STATUS_CODES[result.statusCode]}`);
            })
    })
})
