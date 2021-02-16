# v0.10.106

### FIDO2
- Fixed final issues with HID tests
- Fixed majority of issues that hanged back BLE
- Fixed PKI issues with Safetynet
- Resolved issues with RK tests for authenticators that does not support displays
- Fixed dosen others server issues
- Resolved [#347](https://github.com/fido-alliance/conformance-tools-issues/issues/347), [#345](https://github.com/fido-alliance/conformance-tools-issues/issues/345), [#344](https://github.com/fido-alliance/conformance-tools-issues/issues/344), [#343](https://github.com/fido-alliance/conformance-tools-issues/issues/343), [#342](https://github.com/fido-alliance/conformance-tools-issues/issues/342), [#341](https://github.com/fido-alliance/conformance-tools-issues/issues/341), [#340](https://github.com/fido-alliance/conformance-tools-issues/issues/340), [#338](https://github.com/fido-alliance/conformance-tools-issues/issues/338), [#337](https://github.com/fido-alliance/conformance-tools-issues/issues/337), [#336](https://github.com/fido-alliance/conformance-tools-issues/issues/336), [#334](https://github.com/fido-alliance/conformance-tools-issues/issues/334), [#333](https://github.com/fido-alliance/conformance-tools-issues/issues/333), [#331](https://github.com/fido-alliance/conformance-tools-issues/issues/331)

# v0.10.105

### FIDO2
- Added reset before each test suit
- Added authenticator pin policy tests
- Added authenticator reset tests
- Fixed dosen of issues with PKI and server tests, thanks to @dongho78 s
- Fixed issues with P-10
- Resolved [#330](https://github.com/fido-alliance/conformance-tools-issues/issues/330), [#329](https://github.com/fido-alliance/conformance-tools-issues/issues/329), [#328](https://github.com/fido-alliance/conformance-tools-issues/issues/328), [#327](https://github.com/fido-alliance/conformance-tools-issues/issues/327), [#326](https://github.com/fido-alliance/conformance-tools-issues/issues/326), [#325](https://github.com/fido-alliance/conformance-tools-issues/issues/325), [#324](https://github.com/fido-alliance/conformance-tools-issues/issues/324), [#323](https://github.com/fido-alliance/conformance-tools-issues/issues/323), [#322](https://github.com/fido-alliance/conformance-tools-issues/issues/322), [#321](https://github.com/fido-alliance/conformance-tools-issues/issues/321), [#320](https://github.com/fido-alliance/conformance-tools-issues/issues/320), [#316](https://github.com/fido-alliance/conformance-tools-issues/issues/316), [#285](https://github.com/fido-alliance/conformance-tools-issues/issues/285), [#258](https://github.com/fido-alliance/conformance-tools-issues/issues/258)

# v0.10.104

### FIDO2
- Fixed multiple issue with server tests. Thanks to @dongho78 for reporting
- Update HID P-10 CANCE test up to specs
- Added uncaughtException handler for noble lib, so it doesn't crash the app when running on windows 7
- Added error handling for PCSC interface
- Resolved [#317](https://github.com/fido-alliance/conformance-tools-issues/issues/317), [#315](https://github.com/fido-alliance/conformance-tools-issues/issues/315), [#314](https://github.com/fido-alliance/conformance-tools-issues/issues/314), [#313](https://github.com/fido-alliance/conformance-tools-issues/issues/313), [#312](https://github.com/fido-alliance/conformance-tools-issues/issues/312), [#311](https://github.com/fido-alliance/conformance-tools-issues/issues/311), [#310](https://github.com/fido-alliance/conformance-tools-issues/issues/310), [#309](https://github.com/fido-alliance/conformance-tools-issues/issues/309), [#308](https://github.com/fido-alliance/conformance-tools-issues/issues/308), [#306](https://github.com/fido-alliance/conformance-tools-issues/issues/306), [#305](https://github.com/fido-alliance/conformance-tools-issues/issues/305), [#304](https://github.com/fido-alliance/conformance-tools-issues/issues/304)


# v0.10.103

### UAF1.1
- Fixed issues with ASM userVerification descriptor combinations
- Fixed typoe in regex for ext.data

### FIDO2
- Added MDS tests
- Added error handling for crashes with NFC and BLE libs
- Fixed issues for some server tests "none" was set as attestation
- Resolved [#301](https://github.com/fido-alliance/conformance-tools-issues/issues/301), [#302](https://github.com/fido-alliance/conformance-tools-issues/issues/302), [#297](https://github.com/fido-alliance/conformance-tools-issues/issues/297), [#291](https://github.com/fido-alliance/conformance-tools-issues/issues/291), [#292](https://github.com/fido-alliance/conformance-tools-issues/issues/292), [#293](https://github.com/fido-alliance/conformance-tools-issues/issues/293), [#294](https://github.com/fido-alliance/conformance-tools-issues/issues/294), [#249](https://github.com/fido-alliance/conformance-tools-issues/issues/249), [#299](https://github.com/fido-alliance/conformance-tools-issues/issues/299), [#298](https://github.com/fido-alliance/conformance-tools-issues/issues/298)


# v0.10.102
- Added reset config button

### UAF1.1
- Fixed typoes in extension id length comparison
- Fixed incorrect length check for challenge because of encoding
- Fixed Protocol-Auth-Req-4 P-1 incorrect register appID

### FIDO2
- Added BLE tests
- Improved device management and added device states
- Added NFC state keeping between function calls
- Fixed NFC issue with looping init
- Fixed issue with incorrect signature hash function. Thanks to @prvjhamada
- Resolved [#295](https://github.com/fido-alliance/conformance-tools-issues/issues/295), [#290](https://github.com/fido-alliance/conformance-tools-issues/issues/290), [#289](https://github.com/fido-alliance/conformance-tools-issues/issues/289), [#288](https://github.com/fido-alliance/conformance-tools-issues/issues/288), [#287](https://github.com/fido-alliance/conformance-tools-issues/issues/287), [#286](https://github.com/fido-alliance/conformance-tools-issues/issues/286), [#284](https://github.com/fido-alliance/conformance-tools-issues/issues/284), [#186](https://github.com/fido-alliance/conformance-tools-issues/issues/186)


# v0.10.0/v0.10.100
- Restructured build publishing. Anything v0.10.x is stable. x0.10.1xx is beta in BETA folder.


# v0.9.426
- Fixed issue with inability to select different NFC reader.
- Fixed jumping options


# v0.9.425

### FIDO2
- Added safetynet tests
- Fixed multiple issues with NFC tests. Major thanks to Thomas Duboucher(@serianox) for all his help with Beta testing
- Fixed incorrect TPM attestation signature
- Resolved [#219](https://github.com/fido-alliance/conformance-tools-issues/issues/219), [#266](https://github.com/fido-alliance/conformance-tools-issues/issues/266), [#276](https://github.com/fido-alliance/conformance-tools-issues/issues/276), [#275](https://github.com/fido-alliance/conformance-tools-issues/issues/275), [#278](https://github.com/fido-alliance/conformance-tools-issues/issues/278), [#279](https://github.com/fido-alliance/conformance-tools-issues/issues/279), [#280](https://github.com/fido-alliance/conformance-tools-issues/issues/280), [#277](https://github.com/fido-alliance/conformance-tools-issues/issues/277), [#282](https://github.com/fido-alliance/conformance-tools-issues/issues/282)


# v0.9.424

### FIDO2
- Added NFC support


# v0.9.423

### FIDO2
- Added TPM server tests
- Fixed issus with authToken decryption
- Increased speed of RSA tests by moving them to WebCrypto
- Resolved[#238](https://github.com/fido-alliance/conformance-tools-issues/issues/238), [#252](https://github.com/fido-alliance/conformance-tools-issues/issues/252), [#261](https://github.com/fido-alliance/conformance-tools-issues/issues/261), [#263](https://github.com/fido-alliance/conformance-tools-issues/issues/263), [#264](https://github.com/fido-alliance/conformance-tools-issues/issues/264), [#262](https://github.com/fido-alliance/conformance-tools-issues/issues/262), [#265](https://github.com/fido-alliance/conformance-tools-issues/issues/265), [#267](https://github.com/fido-alliance/conformance-tools-issues/issues/267), [#269](https://github.com/fido-alliance/conformance-tools-issues/issues/269), [#270](https://github.com/fido-alliance/conformance-tools-issues/issues/270), [#271](https://github.com/fido-alliance/conformance-tools-issues/issues/271), [#272](https://github.com/fido-alliance/conformance-tools-issues/issues/272), [#273](https://github.com/fido-alliance/conformance-tools-issues/issues/273)


# v0.9.422

### UAF1.0/1.1
- Resolved incorrect test order in ASM tests

### FIDO2
- TPM attestation support in client tests
- Added RK tests for devices with screen
- Regenerated certificates fixing incorrect OU
- Resolved [#259](https://github.com/fido-alliance/conformance-tools-issues/issues/259), [#224](https://github.com/fido-alliance/conformance-tools-issues/issues/224), [#239](https://github.com/fido-alliance/conformance-tools-issues/issues/239), [#228](https://github.com/fido-alliance/conformance-tools-issues/issues/228), [#243](https://github.com/fido-alliance/conformance-tools-issues/issues/243), [#246](https://github.com/fido-alliance/conformance-tools-issues/issues/246), [#250](https://github.com/fido-alliance/conformance-tools-issues/issues/250), [#225](https://github.com/fido-alliance/conformance-tools-issues/issues/225), [#215](https://github.com/fido-alliance/conformance-tools-issues/issues/215), [#244](https://github.com/fido-alliance/conformance-tools-issues/issues/244), [#220](https://github.com/fido-alliance/conformance-tools-issues/issues/220), [#245](https://github.com/fido-alliance/conformance-tools-issues/issues/245), [#247](https://github.com/fido-alliance/conformance-tools-issues/issues/247), [#251](https://github.com/fido-alliance/conformance-tools-issues/issues/251), [#248](https://github.com/fido-alliance/conformance-tools-issues/issues/248), [#241](https://github.com/fido-alliance/conformance-tools-issues/issues/241), [#236](https://github.com/fido-alliance/conformance-tools-issues/issues/236), [#240](https://github.com/fido-alliance/conformance-tools-issues/issues/240)


# v0.9.421

### FIDO2
- Removed HID F-4 and renamed F-5 to F-4
- Removed some server tests to make test suit more nice
- Added Android Key attestation tests
- Resolved [#237](https://github.com/fido-alliance/conformance-tools-issues/issues/237), [#235](https://github.com/fido-alliance/conformance-tools-issues/issues/235), [#234](https://github.com/fido-alliance/conformance-tools-issues/issues/234), [#233](https://github.com/fido-alliance/conformance-tools-issues/issues/233), [#232](https://github.com/fido-alliance/conformance-tools-issues/issues/232), [#231](https://github.com/fido-alliance/conformance-tools-issues/issues/231), [#230](https://github.com/fido-alliance/conformance-tools-issues/issues/230), [#229](https://github.com/fido-alliance/conformance-tools-issues/issues/229), [#227](https://github.com/fido-alliance/conformance-tools-issues/issues/227), [#226](https://github.com/fido-alliance/conformance-tools-issues/issues/226), [#223](https://github.com/fido-alliance/conformance-tools-issues/issues/223), [#222](https://github.com/fido-alliance/conformance-tools-issues/issues/222)


# v0.9.420

### UAF1.1
- Removed BETA label

### FIDO2
- Client PIN
- Resoled additional HID issues
- Fixed alg value for clientPin
- Resolved [#164](https://github.com/fido-alliance/conformance-tools-issues/issues/164), [#195](https://github.com/fido-alliance/conformance-tools-issues/issues/195), [#218](https://github.com/fido-alliance/conformance-tools-issues/issues/218), [#216](https://github.com/fido-alliance/conformance-tools-issues/issues/216), [#217](https://github.com/fido-alliance/conformance-tools-issues/issues/217)


# v0.9.419

### FIDO2
- Added algorithm server tests.
- Fixed issue with HID P-10
- Resolved [#173](https://github.com/fido-alliance/conformance-tools-issues/issues/173), [#203](https://github.com/fido-alliance/conformance-tools-issues/issues/203), [#204](https://github.com/fido-alliance/conformance-tools-issues/issues/204), [#201](https://github.com/fido-alliance/conformance-tools-issues/issues/201), [#202](https://github.com/fido-alliance/conformance-tools-issues/issues/202), [#194](https://github.com/fido-alliance/conformance-tools-issues/issues/194)


# v0.9.418

### FIDO2
- Fixed incorrect leaf certificate selection that caused incorrect OU check and signature validation
- Fixed incorrect U2F certificates
- Updated endpoints according to the update in the guidelines
- Changed poller timeout to 75ms, so it is twice faster now
- Added authenticator RK tests
- Resolved [#193](https://github.com/fido-alliance/conformance-tools-issues/issues/193), [#199](https://github.com/fido-alliance/conformance-tools-issues/issues/199), [#196](https://github.com/fido-alliance/conformance-tools-issues/issues/196), [#198](https://github.com/fido-alliance/conformance-tools-issues/issues/198), [#197](https://github.com/fido-alliance/conformance-tools-issues/issues/197), [#190](https://github.com/fido-alliance/conformance-tools-issues/issues/190), [#191](https://github.com/fido-alliance/conformance-tools-issues/issues/191), [#192](https://github.com/fido-alliance/conformance-tools-issues/issues/192), [#188](https://github.com/fido-alliance/conformance-tools-issues/issues/188), [#187](https://github.com/fido-alliance/conformance-tools-issues/issues/187), [#180](https://github.com/fido-alliance/conformance-tools-issues/issues/180), [#183](https://github.com/fido-alliance/conformance-tools-issues/issues/183), [#184](https://github.com/fido-alliance/conformance-tools-issues/issues/184), [#185](https://github.com/fido-alliance/conformance-tools-issues/issues/185)


# v0.9.417

### FIDO2
- Increased timeout to 30s
- Resolved [#179](https://github.com/fido-alliance/conformance-tools-issues/issues/179), [#176](https://github.com/fido-alliance/conformance-tools-issues/issues/176), [#164](https://github.com/fido-alliance/conformance-tools-issues/issues/164), [#175](https://github.com/fido-alliance/conformance-tools-issues/issues/175), [#160](https://github.com/fido-alliance/conformance-tools-issues/issues/160), [#161](https://github.com/fido-alliance/conformance-tools-issues/issues/161), [#154](https://github.com/fido-alliance/conformance-tools-issues/issues/154), [#177](https://github.com/fido-alliance/conformance-tools-issues/issues/177), [#153](https://github.com/fido-alliance/conformance-tools-issues/issues/153), [#172](https://github.com/fido-alliance/conformance-tools-issues/issues/172)

### UAF1.0
- Increased timeout to 30s

### UAF1.1
- Increased timeout to 30s


# v0.9.416

- Added node-hid process restart
- Substantially stability of the node-hid module
- Added HID cancel support and CANCEL request after every sendHIDBuffers operation

### FIDO2
- Fixed AAGUID check in Generic P-1
- Update HID tests
- Resolved [#168](https://github.com/fido-alliance/conformance-tools-issues/issues/168), [#169](https://github.com/fido-alliance/conformance-tools-issues/issues/169), [#163](https://github.com/fido-alliance/conformance-tools-issues/issues/163), [#158](https://github.com/fido-alliance/conformance-tools-issues/issues/158), [#167](https://github.com/fido-alliance/conformance-tools-issues/issues/167), [#165](https://github.com/fido-alliance/conformance-tools-issues/issues/165), [#162](https://github.com/fido-alliance/conformance-tools-issues/issues/162), [#166](https://github.com/fido-alliance/conformance-tools-issues/issues/166), [#157](https://github.com/fido-alliance/conformance-tools-issues/issues/157) and [#159](https://github.com/fido-alliance/conformance-tools-issues/issues/159) in https://github.com/fido-alliance/conformance-tools-issues/issues 


# v0.9.415

- Moved NODE-HID to child process

### FIDO2
- Fixed F1 missing test in MakeCred-Req-6. Closed conformance-tools-issues#155


# v0.9.414

- Added buffer logging in the console


# v0.9.413

- Added lock for getInfo while tests are running
- Fixed disappearing button

### FIDO2
- Added server tests

### UAF1.0
- Fixed incorrect signature verification for assertions with custom tags
- Updated iOS tests
- Fixed userVerificationDetails test

### UAF1.1
- Fixed UAF1.1 ASM tcDisplay test
- Fixed UAF1.1/1.0 iOS API F-1 test missing random AAID
- UAF1.1 Increased timeout in before-all hooks 
- Added beforeAll hooks failure message
- UAF1.1/1.0 Fixed some incorrect it/describe/context nesting
- Fixed typoe in metadataStatement reference. Fixed fido-alliance/conformance-tool-issues/148
- Fixed typoe Android getInfo asmVersion test. Fixed fido-alliance/conformance-tool-issues/146
- Fixed title test in ASM tes

# v0.9.412
- Added text/plain to allowed MIME for pollyfills

### FIDO2
- Fixed sorting of numeric values that lead to incorrect key order in cbor map. fido-alliance/conformance-tool-issues#131
- Added device close on return
- Updated tests according to the test plan changes
- Added first example client-pin tests

### UAF
- Fixed UAF1.1 ASM tcDisplay test
- Fixed UAF1.1/1.0 iOS API F-1 test missing random AAID
- UAF1.1 Increased timeout in before-all hooks 
- Added beforeAll hooks failure message
- UAF1.1/1.0 Fixed some incorrect it/describe/context nesting
- Fixed typoe in metadataStatement reference. Fixed fido-alliance/conformance-tool-issues/148
- Fixed typoe Android getInfo asmVersion test. Fixed fido-alliance/conformance-tool-issues/146
- Fixed title test in ASM tests.