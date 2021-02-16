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

        BLE-1

        Test CTAP2 BLE support

    `, function() {

    beforeEach(function() {
        this.timeout(30000);
        return BLEWaitForAuthenticatorToConnect(15000)
    })

    let deviceInfo = undefined;
    before(function(){
        if (!window.config.test.fidoauthenticator)
            throw new Error('No FIDO authenticator available!')

        if(getDeviceInfo().transport !== 'BLE')
            this.skip();
    })

    this.timeout(30000);


/* ---------- Positive Tests ---------- */
    it(`P-1

        Check that authenticator implements Device Information Service(0x180A), and check that:
            (a) It contains "Manufacturer Name String" characteristic(0x2A29).
            (b) It contains "Model Number String" characteristic(0x2A24).
            (c) It contains "Firmware Revision String" characteristic(0x2A26).

    `, () => {
        let services = navigator.fido.fido2.ble.getAllServices(getDeviceInfo());

        assert.isDefined(services['180a'], 'Authenticator MUST implement "Device Information" service!');
        assert.isDefined(services['180a'].characteristics['2a29'], '"Device Information" missing "Manufacturer Name String" characteristic(0x2A29)!');
        assert.isDefined(services['180a'].characteristics['2a24'], '"Device Information" missing "Model Number String" characteristic(0x2A24)!');
        assert.isDefined(services['180a'].characteristics['2a26'], '"Device Information" missing "Firmware Revision String" characteristic(0x2A26)!');
    })

    it(`P-2

        Check that authenticator implements Generic Access Profile Service(0x1800), and check that:
            (a) It contains "Device Name" characteristic(Ox2A00).
            (b) It contains "Appearance" characteristic(0x2A01).

        [SKIPPED DUE TO NOBLE OSX ISSUES]

    `/*, () => {
        let services = navigator.fido.fido2.ble.getAllServices(getDeviceInfo());

        assert.isDefined(services['1800'], 'Authenticator MUST implement "Generic Access Profile" service!');
        assert.isDefined(services['1800'].characteristics['2a00'], '"Generic Access Profile" missing "Device Name" characteristic(0x2A00)!');
        assert.isDefined(services['1800'].characteristics['2a01'], '"Generic Access Profile" missing "Appearance" characteristic(0x2A01)!');
    }*/)

    it(`P-3

        Check that FIDO service is a primary service.

        [SKIPPED DUE TO NOBLE ISSUES]

    `/*, () => {
        assert.strictEqual(navigator.fido.fido2.ble.getPrimaryServiceUUID(getDeviceInfo()), 'fffd', 'Authenticator must have FIDO(0xfffd) service set as primary service!');
    }*/)


    it(`P-4

        Get a list of FIDO characteristics and check that it contains: fidoControlPoint, fidoStatus, fidoControlPointLength and fidoServiceRevisionBitfield characteristics.

    `, () => {
        let characteristics = navigator.fido.fido2.ble.getFIDOCharacteristics(getDeviceInfo());

        assert.isDefined(characteristics.fidoControlPoint, 'Characteristics missing fidoControlPoint.');
        assert.isDefined(characteristics.fidoStatus, 'Characteristics missing fidoStatus.');
        assert.isDefined(characteristics.fidoControlPointLength, 'Characteristics missing fidoControlPointLength.');
        assert.isDefined(characteristics.fidoServiceRevisionBitfield, 'Characteristics missing fidoServiceRevisionBitfield.');
    })

    it(`P-5

       Check that fidoControlPoint characteristic is for "write" and "writeWithoutResponse" only.

    `, () => {
        let characteristics = navigator.fido.fido2.ble.getFIDOCharacteristics(getDeviceInfo());

        assert.includeMembers(characteristics.fidoControlPoint.properties, ['write']);
    })

    it(`P-6

       Check that fidoStatus characteristic is for "notify" only.

    `, () => {
        let characteristics = navigator.fido.fido2.ble.getFIDOCharacteristics(getDeviceInfo());

        assert.includeMembers(characteristics.fidoStatus.properties, ['notify']);
    })

    it(`P-7

       Check that fidoControlPointLength characteristic is for "read" only, and returned value is not below 20 and not higher than 512.

    `, () => {
        let characteristics = navigator.fido.fido2.ble.getFIDOCharacteristics(getDeviceInfo());

        assert.includeMembers(characteristics.fidoControlPointLength.properties, ['read']);

        let maxWriteLen = navigator.fido.fido2.ble.getMaxWriteLength(getDeviceInfo())

        assert.isAtLeast(maxWriteLen, 20, 'Authenticator must support at least 20 bytes packets!');
        assert.isAtMost(maxWriteLen, 512, 'Authenticator must support at most 512 bytes packets!');
    })

    it(`P-8

       Check that fidoServiceRevisionBitfield characteristic contains "read" and "write". Read the characteristic and check that authenticator returns 1 byte that has FIDO2(0x10) flag is set to true.

    `, () => {
        let characteristics = navigator.fido.fido2.ble.getFIDOCharacteristics(getDeviceInfo());
        assert.isDefined(characteristics.fidoServiceRevisionBitfield, 'Characteristics missing fidoServiceRevisionBitfield.');

        assert.isTrue(characteristics.fidoServiceRevisionBitfield.properties.indexOf('read') !== -1, 'Characteristics missing "read" property!');
        assert.isTrue(characteristics.fidoServiceRevisionBitfield.properties.indexOf('write') !== -1, 'Characteristics missing "write" property!');

        let serviceRevisionBitfield = navigator.fido.fido2.ble.getServiceRevisionBitfield(getDeviceInfo());

        assert.isDefined(serviceRevisionBitfield, 'Authenticator does not support fidoServiceRevisionBitfield!');
        assert.isTrue(!!(serviceRevisionBitfield & 0x20), 'fidoServiceRevisionBitfield does not have FIDO2(0x20) bitflag set!');
    })


    it(`P-9

       Send a valid ping command, with a length less than max frame length, and check that authenticator successfully responds with the same frame back.

    `, () => {
        let maxWriteLen = navigator.fido.fido2.ble.getMaxWriteLength(getDeviceInfo());
        let data        = generateRandomBuffer(maxWriteLen - 3);
        let frames      = generateBLERequestFrames(CTAPBLE_CMD.PING, data, getDeviceInfo());
        return navigator.fido.fido2.ble.sendFIDOBuffers(getDeviceInfo(), frames)
            .then((response) => {
                assert.strictEqual(response.CMD, CTAPBLE_CMD.PING, `Sent PING(0x81) command. Got ${CTAPBLE_CMD[response.CMD]}(${response.CMD})`)
                assert.strictEqual(hex.encode(data), hex.encode(response.DATA), `Expected PING to return ${hex.encode(data)}. Got ${hex.encode(response.DATA)}`);
            })
    })

/* ---------- Negative Tests ---------- */

    it(`P-10 

        Send a valid GetAssertion request with invalid credId. Check that authenticator first returns KEEPALIVE(0x82) with error code UP_NEEDED(0x02). Then waiting till authr finally returns CTAP2_ERR_NO_CREDENTIALS(0x2E)

    `)

})
