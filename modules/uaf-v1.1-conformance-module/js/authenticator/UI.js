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

    class UAFUI {
        selectKeyHandle(users, callback) {
            return new Promise((resolve, reject) => {
                /* Throw error if timeout */
                let outTimer = setTimeout(() => {
                    reject(new Error('UAF_CMD_STATUS_ERR_UNKNOWN'));
                }, 30000);

                /* Successfully respond if user is selected */
                let successResponse = (user) => {
                    clearTimeout(outTimer);
                    resolve(user);
                }

                /* Fails user select */
                let failResponse = () => {
                    reject(new Error('UAF_CMD_STATUS_ERR_UNKNOWN'));
                }

                /* Get existing users for such Relying Party */
                callback(users, successResponse, failResponse);
            })
        }

        confirmTransaction(transactionContent, callback) {
            return new Promise((resolve, reject) => {

                /* If transaction content is empty */
                if(!transactionContent)
                    resolve()

                /* Fail */
                let failResponse = () => {
                    clearTimeout(outTimer);
                    reject(new Error('UAF_CMD_STATUS_USER_CANCELLED'));
                }

                /* Throw error if timeout */
                let outTimer = setTimeout(failResponse, 30000);

                /* Successfully respond if user is selected */
                let successResponse = (user) => {
                    clearTimeout(outTimer);
                    resolve(true);
                }

                /* Get existing users for such Relying Party */
                callback(transactionContent, successResponse, failResponse);
            })
        }
    }

    window.UAF.UAFUI = UAFUI;

})()
