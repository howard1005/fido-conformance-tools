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
/**
 * This is the source code for Browser app
 */

const express       = require('express');
const path          = require('path');
const bodyParser    = require('body-parser');
const app           = express();
const crypto        = require('crypto');
const cbor          = require('./dependencies/cbordep');
const fido2crypto   = require('./dependencies/cryptodep');
const nodersa       = require('node-rsa');

app.use(bodyParser.text({type: '*/*'}));

app.use(express.static(path.join(__dirname, 'app')));
app.use('/modules', express.static(path.join(__dirname, 'modules')));

app.use('/eula-fido-conformance-test-tools.pdf', express.static(path.join(__dirname, 'END USER LICENSE AGREEMENT FOR FIDO ALLIANCE FUNCTIONAL CERTIFICATION TEST TOOLS.pdf')));
/* ----- Crypto and CBOR polyfills ----- */
    app.post('/cbor/decodeToJSON', (request, response) => {
        try {
            let cborstruct = cbor.CBORBufferToJSON(Buffer.from(request.body, 'hex'))[0];
            response.json(cborstruct)
        } catch (e) {
            response.json({'status': 'failed', 'error': e.toString()})
        }
    })

    app.post('/cbor/decodeToObjectStruct', (request, response) => {
        try {
            let cborstruct = cbor.CBORBufferToSTRUCTTransportable(Buffer.from(request.body, 'hex'))[0];
            response.json(cborstruct)
        } catch (e) {
            response.json({'status': 'failed', 'error': e.toString()})
        }
    })

    app.post('/crypto/verifySignature', (request, response) => {
        try {
            let payload = JSON.parse(request.body);

            Signature = Buffer.from(payload.sig, 'hex');
            Data      = Buffer.from(payload.msg, 'hex');

            let result = crypto.createVerify('sha256') // The actual signature alg is ECDSA and determined
                .update(Data)                    // by ASN/DER data in public key. SHA256 is what we set here.
                .verify(payload.key, Signature);

            response.json({result})
        } catch (e) {
            response.json({'status': 'failed', 'error': e.toString()})
        }
    })

    app.post('/crypto/sha1', (request, response) => {
        let payload = JSON.parse(request.body);

        Message = Buffer.from(payload.msg, 'hex');

        let hash = crypto.createHash('sha1');
        hash.update(Message);

        let digest = hash.digest('hex')

        response.json({digest})
    })

    app.post('/crypto/verifyPKCS1Signature', (request, response) => {
        try {
            let payload = JSON.parse(request.body);

            Signature = Buffer.from(payload.sig, 'hex');
            Message   = Buffer.from(payload.msg, 'hex');
            Key       = Buffer.from(payload.key, 'hex');
            Scheme    = payload.alg;

            let key = new nodersa(undefined, { signingScheme: Scheme });
            key.importKey({
                n: Key,
                e: 65537
            }, 'components-public');

            let result = key.verify(Message, Signature)

            response.json({result})
        } catch (e) {
            response.json({'status': 'failed', 'error': e.toString()})
        }
    })

    app.post('/crypto/verifySignatureCOSE', (request, response) => {
        let payload = JSON.parse(request.body);

        Signature = Buffer.from(payload.sig, 'hex');
        Message   = Buffer.from(payload.msg, 'hex');
        Key       = Buffer.from(payload.key, 'hex');

        let result = fido2crypto.verifySignatureCOSE(Key, Message, Signature)

        response.json({result})
    })
/* ----- Crypto and CBOR polyfills ----- */


const port = 0xF1D0;
app.listen(port);
console.log(`Started webserver on port ${port}`);
module.exports = app;
