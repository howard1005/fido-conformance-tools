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

        WebAuthn-Platform-MakeCred-Req-4

        Test platform processing PublicKeyCredentialUserEntity

    `, function() {

    beforeEach(function() {
        this.timeout(10000)
        return TimeoutPromise(2000)
    })
    this.timeout(120000);

/* ----- POSITIVE TESTS ----- */
    it(`P-1

        Send a valid MakeCredential request with PublicKeyCredentialUserEntity.icon set to some HTTPS url, and check that API succeeds

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
        publicKey.user.icon = 'https://static.certinfra.fidoalliance.org/testimages/fidoicon.png';

        return navigator.credentials.create({ publicKey })
    })

    it(`P-2

        Send a valid MakeCredential request with PublicKeyCredentialUserEntity.icon set to some URL encoded image, and check that API succeeds

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
        publicKey.user.icon = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAAACXBIWXMAAA3XAAAN1wFCKJt4AAADGGlDQ1BQaG90b3Nob3AgSUNDIHByb2ZpbGUAAHjaY2BgnuDo4uTKJMDAUFBUUuQe5BgZERmlwH6egY2BmYGBgYGBITG5uMAxIMCHgYGBIS8_L5UBFTAyMHy7xsDIwMDAcFnX0cXJlYE0wJpcUFTCwMBwgIGBwSgltTiZgYHhCwMDQ3p5SUEJAwNjDAMDg0hSdkEJAwNjAQMDg0h2SJAzAwNjCwMDE09JakUJAwMDg3N-QWVRZnpGiYKhpaWlgmNKflKqQnBlcUlqbrGCZ15yflFBflFiSWoKAwMD1A4GBgYGXpf8EgX3xMw8BSMDVQYqg4jIKAUICxE-CDEESC4tKoMHJQODAIMCgwGDA0MAQyJDPcMChqMMbxjFGV0YSxlXMN5jEmMKYprAdIFZmDmSeSHzGxZLlg6WW6x6rK2s99gs2aaxfWMPZ9_NocTRxfGFM5HzApcj1xZuTe4FPFI8U3mFeCfxCfNN45fhXyygI7BD0FXwilCq0A_hXhEVkb2i4aJfxCaJG4lfkaiQlJM8JpUvLS19QqZMVl32llyfvIv8H4WtioVKekpvldeqFKiaqP5UO6jepRGqqaT5QeuA9iSdVF0rPUG9V_pHDBYY1hrFGNuayJsym740u2C-02KJ5QSrOutcmzjbQDtXe2sHY0cdJzVnJRcFV3k3BXdlD3VPXS8Tbxsfd99gvwT__ID6wIlBS4N3hVwMfRnOFCEXaRUVEV0RMzN2T9yDBLZE3aSw5IaUNak30zkyLDIzs-ZmX8xlz7PPryjYVPiuWLskq3RV2ZsK_cqSql01jLVedVPrHzbqNdU0n22VaytsP9op3VXUfbpXta-x_-5Em0mzJ_-dGj_t8AyNmf2zvs9JmHt6vvmCpYtEFrcu-bYsc_m9lSGrTq9xWbtvveWGbZtMNm_ZarJt-w6rnft3u-45uy9s_4ODOYd-Hmk_Jn58xUnrU-fOJJ_9dX7SRe1LR68kXv13fc5Nm1t379TfU75_4mHeY7En-59lvhB5efB1_lv5dxc-NH0y_fzq64Lv4T8Ffp360_rP8f9_AA0ADzT6lvFdAAAAIGNIUk0AAHolAACAgwAA-f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAFDSURBVHjazJHRcdswEESfPWlgW7gW0AJcAlwCWkALVAlgCVIJVAlkCVQJQgmbD4n2OMkknzG-boA3e9jdF_P388r_AsZ2O0bbbpKkri5JebebUNpt2z8AbjRgjDFqjPltuZxK3U5v-4dCkW1PTEz2mapke6J_KMA7pOfOopkCZLZ_uRgAT4UzcDqu87YBt4fmbwrjfdS4XmFW_sMnJal5D-WgfdqsGaBQAHIi1nnLuQDw8g3afObARujLw3ZEa9veA9RSspt2d_VzgM62jW3fI_paQbvF5KqutCxZywE8ikvQz5AckbXaq6YDeCTpldoIrapK9rqu918AKyI6ma7iCSgHUFlsp1RFuwvtIXtdVGy_AmRmmLecBkmBoowT6TI-bTYiK-67ZE9UO5NCKrafZc1XUoM5MrdLCZivKpC_R5s_BwAydO6pL0AlDgAAAABJRU5ErkJggg';

        return navigator.credentials.create({ publicKey })
    })
/* ----- NEGATIVE TESTS ----- */

    describe(`F-1

        Send two MakeCredential requests with PublicKeyCredentialUserEntity.id set to undefined and check that API fails

    `, () => {
        it(`PublicKeyCredentialUserEntity.user.id = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.user.id = undefined;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    describe(`F-2

        Send two MakeCredential requests with PublicKeyCredentialUserEntity.name set to undefined and check that API fails

    `, () => {
        it(`PublicKeyCredentialUserEntity.user.name = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.user.name = undefined;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    describe(`F-3

        Send two MakeCredential requests with PublicKeyCredentialUserEntity.displayName set to undefined and check that API fails

    `, () => {
        it(`PublicKeyCredentialUserEntity.user.displayName = undefined`, () => {
            let publicKey = generateGoodWebAuthnMakeCredential();
            publicKey.user.displayName = undefined;
            return expectPromiseToFail(navigator.credentials.create({ publicKey }))
        })
    })

    it(`F-8

        Send MakeCredential request with PublicKeyCredentialUserEntity.icon set to some HTTP url, and check that API fails

    `, () => {
        let publicKey = generateGoodWebAuthnMakeCredential();
        publicKey.user.icon = 'http://static.certinfra.fidoalliance.org/testimages/fidoicon.png';
        return expectPromiseToFail(navigator.credentials.create({ publicKey }))
    })

    // it(`F-9

    //     Send MakeCredential request with PublicKeyCredentialUserEntity.icon set to some HTTPS url that is then downgraded to HTTP, and check that API fails

    // `, () => {
    //     let publicKey = generateGoodWebAuthnMakeCredential();
    //     publicKey.user.icon = 'https://static.certinfra.fidoalliance.org/imagedowngrade/fidoicon.png';
    //     return expectPromiseToFail(navigator.credentials.create({ publicKey }))
    // })
})
