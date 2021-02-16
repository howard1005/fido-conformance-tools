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

let generateGoodWebAuthnMakeCredential = () => {
    let challenge = generateRandomBuffer(32);

    let rp = {
        name: 'The Example Corporation with fake domain!'
    }

    let randomUserDomain = generateRandomDomain();
    let randomUserName   = generateRandomName();

    let user = {
        id: generateRandomBuffer(32),
        icon: 'https://pics.acme.com/00/p/aBjjjpqPb.png',
        name: generateEmailFromNameAndDomain(randomUserName, randomUserDomain),
        displayName: randomUserName
    }

    let attestation = 'none';

    let metadataStatement = getMetadataStatement();
    let fidoAuthAlg       = AUTHENTICATION_ALGORITHMS[metadataStatement.authenticationAlgorithm];
    let coseParams        = FIDO_ALG_TO_COSE[fidoAuthAlg];

    if(!coseParams)
        throw new Error(`${metadataStatement.authenticationAlgorithm} is an unknown FIDO algorithm identifier!`);

    let pubKeyCredParams  = [
        {
            type: 'public-key',
            alg: coseParams.alg
        }
    ]

    let authenticatorSelection = {
        'authenticatorAttachment': 'platform'
    }

    return {
        challenge, rp, user, attestation, pubKeyCredParams, authenticatorSelection
    }
}

let generateGoodWebAuthnGetAssertion = (credId) => {
    let challenge        = generateRandomBuffer(32);
    let allowCredentials = [{'type': 'public-key', 'id': credId}]

    return {
        challenge, allowCredentials
    }
}

