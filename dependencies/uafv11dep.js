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

const https = require('https');

module.exports = {
    'getFIDORedirectHeader' : (url) => {
        return new Promise((resolve, reject) => {
            https.get(url, (response) => {
                if (response.statusCode !== 301 && response.statusCode !== 302)
                    reject(new Error(`No redirect been detected. Server returned ${response.statusCode} statusCode!`));
                
                resolve(response.headers['fido-appid-redirect-authorized'])
            }).on('error', (error) => {
                reject(`Error while requesting given URL(${url}). Message ${error}`);
            });
        })
    }
}