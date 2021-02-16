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
 * FIDO UAF Protocols metadata
 */


/**
 * List of UAF protocol status codes.
 * 
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-client-api-transport-v1.0-ps-20141208.html#uaf-status-codes 
 * 
 * type {Object}
 */
var STATUS_CODES = {
    1200 : 'OK. Operation completed',
    1202 : 'Accepted. Message accepted, but not completed at this time. The RP may need time to, process the attestation, run risk scoring, etc. The server should not send an authenticationToken with a 1202 response',
    1400 : 'Bad Request. The server did not understand the message',
    1401 : 'Unauthorized. The userid must be authenticated to perform this operation, or this, KeyID is not associated with this UserID.',
    1403 : 'Forbidden. The userid is not allowed to perform this operation. Client should not, retry',
    1404 : 'Not Found.',
    1408 : 'Request Timeout.',
    1480 : 'Unknown AAID. The server was unable to locate authoritative metadata for the AAID.',
    1481 : 'Unknown KeyID. The server was unable to locate a registration for the given UserID, and KeyID combination. This error indicates that there is an invalid registration on the user\'s device. It is recommended that FIDO UAF Client deletes the key from local device when this error is received.',
    1490 : 'Channel Binding Refused. The server refused to service the request due to a missing, or mismatched channel binding(s).',
    1491 : 'Request Invalid. The server refused to service the request because the request, message nonce was unknown, expired or the server has previously serviced a message with the same nonce and user ID.',
    1492 : 'Unacceptable Authenticator. The authenticator is not acceptable according to the, server\'s policy, for example because the capability registry used by the server reported different capabilities than client-side discovery.',
    1493 : 'Revoked Authenticator. The authenticator is considered revoked by the server.',
    1494 : 'Unacceptable Key. The key used is unacceptable. Perhaps it is on a list of known weak, keys or uses insecure parameter choices.',
    1495 : 'Unacceptable Algorithm. The server believes the authenticator to be capable of using, a stronger mutually-agreeable algorithm than was presented in the request.',
    1496 : 'Unacceptable Attestation. The attestation(s) provided were not accepted by the server,.',
    1497 : 'Unacceptable Client Capabilities. The server was unable or unwilling to use required, capabilities provided supplementally to the authenticator by the client software.',
    1498 : 'Unacceptable Content. There was a problem with the contents of the message and the, server  was unwilling or unable to process it.',
    1500 : 'Internal Server Error'
}


var ASM_STATUS_CODES = {
    /* No error condition encountered. */ 
    0x00 : 'UAF_ASM_STATUS_OK',

    /* An unknown error has been encountered during the processing. */
    0x01 : 'UAF_ASM_STATUS_ERROR',
    
    /* Access to this request is denied. */
    0x02 : 'UAF_ASM_STATUS_ACCESS_DENIED',

    /* Indicates that user explicitly canceled the request. */
    0x03 : 'UAF_ASM_STATUS_USER_CANCELLED',

    /* Transaction content cannot be rendered, e.g. format doesn't fit authenticator's need. */
    0x04 : 'UAF_ASM_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT',

    /* Indicates that the UAuth key disappeared from the authenticator and canot be restored. */
    0x09 : 'UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY',

    /* Indicates that the authenticator is no longer connected to the ASM. */
    0x0b : 'UAF_ASM_STATUS_AUTHENTICATOR_DISCONNECTED',

    /* The user took too long to follow an instruction, e.g. didn't swipe the finger within the accepted time. */
    0x0e : 'UAF_ASM_STATUS_USER_NOT_RESPONSIVE',

    /* Insufficient resources in the authenticator to perform the requested task. */
    0x0f : 'UAF_ASM_STATUS_INSUFFICIENT_AUTHENTICATOR_RESOURCES',

    /* The operation failed because the user is locked out and the authenticator cannot automatically trigger an action to change that. Typically the user would have to enter an alternative password (formally: undergo some other alternative user verification method) to re-enable the use of the main user verification method. */
    0x10 : 'UAF_ASM_STATUS_USER_LOCKOUT',

    /* The operation failed because the user is not enrolled to the authenticator and the authenticator cannot automatically trigger user enrollment. */
    0x11 : 'UAF_ASM_STATUS_USER_NOT_ENROLLED'
}


/**
 * ErrorCode interface
 *
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-client-api-transport-v1.0-ps-20141208.html#errorcode-interface
 * 
 * type {Object}
 */
var INTERFACE_STATUS_CODES = {
    /* The operation completed with no error condition encountered. Upon receipt of this code, an application should no longer expect an associated UAFResponseCallback to fire. */
    0x00  : 'NO_ERROR',
    
    /* Waiting on user action to proceed. For example, selecting an authenticator in the FIDO client user interface, performing user verification, or completing an enrollment step with an authenticator. */
    0x01  : 'WAIT_USER_ACTION',
    
    /* window.location.protocol is not "https" or the DOM contains insecure mixed content. */
    0x02  : 'INSECURE_TRANSPORT',
    
    /* The user declined any necessary part of the interaction to complete the registration. */
    0x03  : 'USER_CANCELLED',
    
    /* The UAFMessage does not specify a protocol version supported by this FIDO UAF Client. */
    0x04  : 'UNSUPPORTED_VERSION',
    
    /* No authenticator matching the authenticator policy specified in the UAFMessage is available to service the request, or the user declined to consent to the use of a suitable authenticator. */
    0x05  : 'NO_SUITABLE_AUTHENTICATOR',
    
    /* A violation of the UAF protocol occurred. The interaction may have timed out; the origin associated with the message may not match the origin of the calling DOM context, or the protocol message may be malformed or tampered with. */
    0x06  : 'PROTOCOL_ERROR',
    
    /* The client declined to process the operation because the caller's calculated facet identifier was not found in the trusted list for the application identifier specified in the request message. */
    0x07  : 'UNTRUSTED_FACET_ID',

    /* The UAuth key disappeared from the authenticator and canot be restored. */
    0x09  : 'KEY_DISAPPEARED_PERMANENTLY',

    /* The authenticator denied access to the resulting request. */
    0x0c  : 'INVALID_TRANSACTION_CONTENT',

    /* Transaction content cannot be rendered, e.g. format doesn't fit authenticator's need. */
    0x0d  : 'USER_NOT_RESPONSIVE',

    /* The user took too long to follow an instruction, e.g. didn't swipe the finger within the accepted time. */
    0x0e  : 'USER_NOT_RESPONSIVE',

    /* Insufficient resources in the authenticator to perform the requested task. */
    0x0f  : 'INSUFFICIENT_AUTHENTICATOR_RESOURCES',

    /* The operation failed because the user is locked out and the authenticator cannot automatically trigger an action to change that. For example, an authenticator could allow the user to enter an alternative password to re-enable the use of fingerprints after too many failed finger verification attempts. This error will be reported if such method either doesn't exist or the ASM / authenticator cannot automatically trigger it. */
    0x10  : 'USER_LOCKOUT',

    /* The operation failed because the user is not enrolled to the authenticator and the authenticator cannot automatically trigger user enrollment. */
    0x11  : 'USER_NOT_ENROLLED',

    /* An error condition not described by the above-listed codes. */
    0xFF : 'UNKNOWN'
}

/**
 * 5.4 Status Codes
 */
var CMD_STATUS_CODES = {
    /* Success */
    0x00 : 'UAF_CMD_STATUS_OK',
    /* An unknown error */
    0x01 : 'UAF_CMD_STATUS_ERR_UNKNOWN',
    /* Access to this operation is denied */
    0x02 : 'UAF_CMD_STATUS_ACCESS_DENIED',
    /* User is not enrolled with the authenticator */
    0x03 : 'UAF_CMD_STATUS_USER_NOT_ENROLLED',
    /* Transaction content cannot be rendered */
    0x04 : 'UAF_CMD_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT',
    /* User has cancelled the operation */
    0x05 : 'UAF_CMD_STATUS_USER_CANCELLED',
    /* Command not supported */
    0x06 : 'UAF_CMD_STATUS_CMD_NOT_SUPPORTED',
    /* Required attestation not supported */
    0x07 : 'UAF_CMD_STATUS_ATTESTATION_NOT_SUPPORTED',
    /* The parameters for the command received by the authenticator are malformed/invalid. */
    0x08 : 'UAF_CMD_STATUS_PARAMS_INVALID',
    /* The UAuth key which is relevant for this command disappeared from the authenticator and cannot be restored. On some authenticators this error occurs when the user verification reference data set was modified (e.g. new fingerprint template added). */
    0x09 : 'UAF_CMD_STATUS_KEY_DISAPPEARED_PERMANENTLY',
    /* The operation in the authenticator took longer than expected (due to technical issues) and it was finally aborted. */
    0x0a : 'UAF_CMD_STATUS_TIMEOUT',
    /* The user took too long to follow an instruction, e.g. didn't swipe the finger within the accepted time. */
    0x0e : 'UAF_CMD_STATUS_USER_NOT_RESPONSIVE',
    /* Insufficient resources in the authenticator to perform the requested task. */
    0x0f : 'UAF_CMD_STATUS_INSUFFICIENT_RESOURCES',
    /* The operation failed because the user is locked out and the authenticator cannot automatically trigger an action to change that. Typically the user would have to enter an alternative password (formally: undergo some other alternative user verification method) to re-enable the use of the main user verification method. */
    0x10 : 'UAF_CMD_STATUS_USER_LOCKOUT',
}

/**
 * User Verification Methods
 *
 * The USER_VERIFY constants are flags in a bitfield represented as a 32 bit long integer. They describe the methods and capabilities of an UAF authenticator for locally verifying a user. The operational details of these methods are opaque to the server. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages.
 *
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#user-verification-methods
 * 
 * type {Object}
 */
var USER_VERIFICATION_METHODS = {
    /* This flag must be set if the authenticator is able to confirm user presence in any fashion. If this flag and no other is set for user verification, the guarantee is only that the authenticator cannot be operated without some human intervention, not necessarily that the presence verification provides any level of authentication of the human's identity. (e.g. a device that requires a touch to activate)*/
    0x01 : 'USER_VERIFY_PRESENCE',

    /* This flag must be set if the authenticator uses any type of measurement of a fingerprint for user verification.*/
    0x02 : 'USER_VERIFY_FINGERPRINT',

    /* This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification.*/
    0x04 : 'USER_VERIFY_PASSCODE',

    /* This flag must be set if the authenticator uses a voiceprint (also known as speaker recognition) for user verification.*/
    0x08 : 'USER_VERIFY_VOICEPRINT',

    /* This flag must be set if the authenticator uses any manner of face recognition to verify the user.*/
    0x10 : 'USER_VERIFY_FACEPRINT',

    /* This flag must be set if the authenticator uses any form of location sensor or measurement for user verification.*/
    0x20 : 'USER_VERIFY_LOCATION',

    /* This flag must be set if the authenticator uses any form of eye biometrics for user verification.*/
    0x40 : 'USER_VERIFY_EYEPRINT',

    /* This flag must be set if the authenticator uses a drawn pattern for user verification.*/
    0x80 : 'USER_VERIFY_PATTERN',

    /* This flag must be set if the authenticator uses any measurement of a full hand (including palm-print, hand geometry or vein geometry) for user verification.*/
    0x100 : 'USER_VERIFY_HANDPRINT',

    /* This flag must be set if the authenticator will respond without any user interaction (e.g. Silent Authenticator).*/
    0x200 : 'USER_VERIFY_NONE',

    /* If an authenticator sets multiple flags for user verification types, it may also set this flag to indicate that all verification methods will be enforced (e.g. faceprint AND voiceprint). If flags for multiple user verification methods are set and this flag is not set, verification with only one is necessary (e.g. fingerprint OR passcode).*/
    0x400 : 'USER_VERIFY_ALL'
}


/**
 * Key Protection Types
 *
 * The KEY_PROTECTION constants are flags in a bit field represented as a 16 bit long integer. They describe the method an authenticator uses to protect the private key material for FIDO registrations. Refer to [UAFAuthnrCommands] for more details on the relevance of keys and key protection. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages.
 *
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#key-protection-types
 * type {Object}
 */
var KEY_PROTECTION_TYPES = {

    /* This flag must be set if the authenticator uses software-based key management. Exclusive in authenticator metadata with KEY_PROTECTION_HARDWARE, KEY_PROTECTION_TEE, KEY_PROTECTION_SECURE_ELEMENT*/
    0x01 : 'KEY_PROTECTION_SOFTWARE',

    /* This flag should be set if the authenticator uses hardware-based key management. Exclusive in authenticator metadata with KEY_PROTECTION_SOFTWARE*/
    0x02 : 'KEY_PROTECTION_HARDWARE',

    /* This flag should be set if the authenticator uses the Trusted Execution Environment [TEE] for key management. In authenticator metadata, this flag should be set in conjunction with KEY_PROTECTION_HARDWARE. Exclusive in authenticator metadata with KEY_PROTECTION_SOFTWARE, KEY_PROTECTION_SECURE_ELEMENT*/
    0x04 : 'KEY_PROTECTION_TEE',

    /* This flag should be set if the authenticator uses a Secure Element [SecureElement] for key management. In authenticator metadata, this flag should be set in conjunction with KEY_PROTECTION_HARDWARE. Exclusive in authenticator metadata with KEY_PROTECTION_TEE, KEY_PROTECTION_SOFTWARE*/
    0x08 : 'KEY_PROTECTION_SECURE_ELEMENT',

    /* This flag must be set if the authenticator does not store (wrapped) UAuth keys at the client, but relies on a server-provided key handle. This flag must be set in conjunction with one of the other KEY_PROTECTION flags to indicate how the local key handle wrapping key and operations are protected. Servers may unset this flag in authenticator policy if they are not prepared to store and return key handles, for example, if they have a requirement to respond indistinguishably to authentication attempts against userIDs that do and do not exist. Refer to [UAFProtocol] for more details.*/
    0x10 : 'KEY_PROTECTION_REMOTE_HANDLE'
}


/**
 * Matcher Protection Types
 *
 * The MATCHER_PROTECTION constants are flags in a bit field represented as a 16 bit long integer. They describe the method an authenticator uses to protect the matcher that performs user verification. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages. Refer to [UAFAuthnrCommands] for more details on the matcher component.
 * 
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#matcher-protection-types
 * 
 * type {Object}
 */
var MATCHER_PROTECTION_TYPES = {

    /*This flag must be set if the authenticator's matcher is running in software. Exclusive in authenticator metadata with MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_ON_CHIP*/
    0x01 : 'MATCHER_PROTECTION_SOFTWARE',
    
    /*This flag should be set if the authenticator's matcher is running inside the Trusted Execution Environment [TEE]. Exclusive in authenticator metadata with MATCHER_PROTECTION_SOFTWARE, MATCHER_PROTECTION_ON_CHIP*/
    0x02 : 'MATCHER_PROTECTION_TEE',
    
    /*This flag should be set if the authenticator's matcher is running on the chip. Exclusive in authenticator metadata with MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_SOFTWARE*/
    0x04 : 'MATCHER_PROTECTION_ON_CHIP'
}


/**
 * Authenticator Attachment Hints
 *
 * The ATTACHMENT_HINT constants are flags in a bit field represented as a 32 bit long. They describe the method an authenticator uses to communicate with the FIDO User Device. These constants are reported and queried through the UAF Discovery APIs [UAFAppAPIAndTransport], and used to form Authenticator policies in UAF protocol messages. Because the connection state and topology of an authenticator may be transient, these values are only hints that can be used by server-supplied policy to guide the user experience, e.g. to prefer a device that is connected and ready for authenticating or confirming a low-value transaction, rather than one that is more secure but requires more user effort.
 * 
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#authenticator-attachment-hints
 * 
 * type {Object}
 */
var AUTHENTICATOR_ATTACHMENT_HINTS = {

    /* This flag may be set to indicate that the authenticator is permanently attached to the FIDO User Device. A device such as a smartphone may have authenticator functionality that is able to be used both locally and remotely. In such a case, the FIDO client must filter and exclusively report only the relevant bit during Discovery and when performing policy matching.\nThis flag cannot be combined with any other ATTACHMENT_HINT flags.*/
    0x01 : 'ATTACHMENT_HINT_INTERNAL',

    /* This flag may be set to indicate, for a hardware-based authenticator, that it is removable or remote from the FIDO User Device.\nA device such as a smartphone may have authenticator functionality that is able to be used both locally and remotely. In such a case, the FIDO UAF Client must filter and exclusively report only the relevant bit during discovery and when performing policy matching.*/
    0x02 : 'ATTACHMENT_HINT_EXTERNAL',

    /* This flag may be set to indicate that an external authenticator currently has an exclusive wired connection, e.g. through USB, Firewire or similar, to the FIDO User Device.*/
    0x04 : 'ATTACHMENT_HINT_WIRED',

    /* This flag may be set to indicate that an external authenticator communicates with the FIDO User Device through a personal area or otherwise non-routed wireless protocol, such as Bluetooth or NFC.*/
    0x08 : 'ATTACHMENT_HINT_WIRELESS',

    /* This flag may be set to indicate that an external authenticator is able to communicate by NFC to the FIDO User Device. As part of authenticator metadata, or when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set as well.*/
    0x10 : 'ATTACHMENT_HINT_NFC',

    /* This flag may be set to indicate that an external authenticator is able to communicate using Bluetooth with the FIDO User Device. As part of authenticator metadata, or when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set.*/
    0x20 : 'ATTACHMENT_HINT_BLUETOOTH',

    /* This flag may be set to indicate that the authenticator is connected to the FIDO User Device ver a non-exclusive network (e.g. over a TCP/IP LAN or WAN, as opposed to a PAN or point-to-point connection).*/
    0x40 : 'ATTACHMENT_HINT_NETWORK',

    /* Thif flag may be set to indicate that an external authenticator is in a "ready" state. This flag is set by the ASM at its discretion.*/
    0x80 : 'ATTACHMENT_HINT_READY',

    /* This flag may be set to indicate that an external authenticator is able to communicate using WiFi Direct with the FIDO User Device. As part of authenticator metadata and when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set.*/
    0x100 : 'ATTACHMENT_HINT_WIFI_DIRECT'
}


/**
 * Transaction Confirmation Display Types
 *
 * The TRANSACTION_CONFIRMATION_DISPLAY constants are flags in a bit field represented as a 16 bit long integer. They describe the availability and implementation of a transaction confirmation display capability required for the transaction confirmation operation. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages. Refer to [UAFAuthnrCommands] for more details on the security aspects of TransactionConfirmation Display.
 *
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#transaction-confirmation-display-types
 * type {Object}
 */
var TRANSACTION_CONFIRMATION_DISPLAY_TYPES = {
    /* This flag must be set to indicate, that some form of transaction confirmation display is available on this authenticator.*/
    0x01 : 'TRANSACTION_CONFIRMATION_DISPLAY_ANY',

    /* This flag must be set to indicate, that a software-based transaction confirmation display operating in a privileged context is available on this authenticator.\nA FIDO client that is capable of providing this capability may set this bit for all authenticators of type ATTACHMENT_HINT_INTERNAL, even if the authoritative metadata for the authenticator does not indicate this capability.*/
    0x02 : 'TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE',

    /* This flag should be set to indicate that the authenticator implements a transaction confirmation display in a Trusted Execution Environment ([TEE], [TEESecureDisplay]).*/
    0x04 : 'TRANSACTION_CONFIRMATION_DISPLAY_TEE',

    /* This flag should be set to indicate that a transaction confirmation display based on hardware assisted capabilities is available on this authenticator.*/
    0x08 : 'TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE',

    /* This flag should be set to indicate that the transaction confirmation display is provided on a distinct device from the FIDO User Device.*/
    0x10 : 'TRANSACTION_CONFIRMATION_DISPLAY_REMOTE'
}


/**
 * Authentication Algorithms
 * 
 * The UAF_ALG_SIGN constants are 16 bit long integers indicating the specific signature algorithm and encoding.
 *
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#authentication-algorithms
 * 
 * type {Object}
 */
var AUTHENTICATION_ALGORITHMS = {

    /**
     * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
     *I.e. [R (32 bytes), S (32 bytes)]
     */
    0x0001 : 'ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW',

    /**
     * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
     * DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the NIST secp256r1 curve.
     * I.e. a DER encoded SEQUENCE { r INTEGER, s INTEGER }
     */
    0x0002 : 'ALG_SIGN_SECP256R1_ECDSA_SHA256_DER',

    /**
     * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
     * RSASSA-PSS [RFC3447] signature must have raw S buffers, encoded in big-endian order [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
     * - Mask Generation Algorithm MGF1 with SHA256
     * - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
     * - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
     * I.e. [ S (256 bytes) ]
     */
    0x0003 : 'ALG_SIGN_RSASSA_PSS_SHA256_RAW',

    /**
     * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
     * DER [ITU-X690-2008] encoded OCTET STRING (not BIT STRING!) containing the RSASSA-PSS [RFC3447] signature [RFC4055] [RFC4056]. The default parameters as specified in [RFC4055] must be assumed, i.e.
     * - Mask Generation Algorithm MGF1 with SHA256
     * - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
     * - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
     * I.e. a DER encoded OCTET STRING (including its tag and length bytes).
     */
    0x0004 : 'ALG_SIGN_RSASSA_PSS_SHA256_DER',

    /**
     * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
     * An ECDSA signature on the secp256k1 curve which must have raw R and S buffers, encoded in big-endian order.
     * I.e.[R (32 bytes), S (32 bytes)]
     */
    0x0005 : 'ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW',


    /**
     * An ECDSA signature on the NIST secp256r1 curve which must have raw R and S buffers, encoded in big-endian order.
     * DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the secp256k1 curve.
     * I.e. a DER encoded SEQUENCE { r INTEGER, s INTEGER }
     */
    0x0006 : 'ALG_SIGN_SECP256K1_ECDSA_SHA256_DER',

    /**
     * Chinese SM2 elliptic curve based signature algorithm combined with SM3 hash algorithm [OSCCA-SM2][OSCCA-SM3]. We use the 256bit curve [OSCCA-SM2-curve-param].
     * This algorithm is suitable for authenticators using the following key representation format: ALG_KEY_ECC_X962_RAW.
     */
    0x0007 : 'ALG_SIGN_SM2_SM3_RAW',

    /**
     * This is the EMSA-PKCS1-v1_5 signature as defined in [RFC3447]. This means that the encoded message EM will be the input to the cryptographic signing algorithm RSASP1 as defined in [RFC3447]. The result s of RSASP1 is then encoded using function I2OSP to produce the raw signature octets.
     ** EM = 0x00 | 0x01 | PS | 0x00 | T
     ** with the padding string PS with length=emLen - tLen - 3 octets having the value 0xff for each octet, e.g. (0x) ff ff ff ff ff ff ff ff
     ** with the DER [ITU-X690-2008] encoded DigestInfo value T: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 | H, where H denotes the bytes of the SHA256 hash value.
     * This algorithm is suitable for authenticators using the following key representation formats:
     ** ALG_KEY_RSA_2048_RAW
     ** ALG_KEY_RSA_2048_DER
     */
    0x0008 : 'ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW',


    /**
     * DER [ITU-X690-2008] encoded OCTET STRING (not BIT STRING!) containing the EMSA-PKCS1-v1_5 signature as defined in [RFC3447]. This means that the encoded message EM will be the input to the cryptographic signing algorithm RSASP1 as defined in [RFC3447]. The result s of RSASP1 is then encoded using function I2OSP to produce the raw signature. The raw signature is DER [ITU-X690-2008] encoded as an OCTET STRING to produce the final signature octets.
     ** EM = 0x00 | 0x01 | PS | 0x00 | T
     ** with the padding string PS with length=emLen - tLen - 3 octets having the value 0xff for each octet, e.g. (0x) ff ff ff ff ff ff ff ff
     ** with the DER encoded DigestInfo value T: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 | H, where H denotes the bytes of the SHA256 hash value.
     * This algorithm is suitable for authenticators using the following key representation formats:
     ** ALG_KEY_RSA_2048_RAW
     ** ALG_KEY_RSA_2048_DER
     */
    0x0009 : 'ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER'   
}


/**
 * Public Key Representation Formats
 *
 * The UAF_ALG_KEY constants are 16 bit long integers indicating the specific Public Key algorithm and encoding.
 *
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#public-key-representation-formats
 * 
 * type {Object}
 */
var PUBLIC_KEY_REPRESENTATION_FORMATS = {

    /** 
     * Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
     * 
     * I.e. [0x04, X (32 bytes), Y (32 bytes)]. Where the byte 0x04 denotes the uncompressed point compression method.
     */
    0x100 : 'ALG_KEY_ECC_X962_RAW',

    /** 
     * 
     * DER [ITU-X690-2008] encoded ANSI X.9.62 formatted SubjectPublicKeyInfo [RFC5480] specifying an elliptic curve public key.
     * 
     * I.e. a DER encoded SubjectPublicKeyInfo as defined in [RFC5480].
     * 
     * Authenticator implementations must generate namedCurve in the ECParameters object which is included in the AlgorithmIdentifier. A FIDO UAF Server must accept namedCurve in the ECParameters object which is included in the AlgorithmIdentifier.
     */
    0x101 : 'ALG_KEY_ECC_X962_DER',

    /** 
     * Raw encoded RSASSA-PSS public key [RFC3447].
     * The default parameters according to [RFC4055] must be assumed, i.e.
     *
     *  - Mask Generation Algorithm MGF1 with SHA256
     *  - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
     *  - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
     * 
     * That is, [n (256 bytes), e (N-n bytes)]. Where N is the total length of the field.
     *
     * This total length should be taken from the object containing this key, e.g. the TLV encoded field.
     */
    0x102 : 'ALG_KEY_RSA_2048_PSS_RAW',

    /** 
     * 
     * ASN.1 DER [ITU-X690-2008] encoded RSASSA-PSS [RFC3447] public key [RFC4055].
     * The default parameters according to [RFC4055] must be assumed, i.e.
     * 
     *  - Mask Generation Algorithm MGF1 with SHA256
     *  - Salt Length of 32 bytes, i.e. the length of a SHA256 hash value.
     *  - Trailer Field value of 1, which represents the trailer field with hexadecimal value 0xBC.
     * 
     * That is, a DER encoded SEQUENCE { n INTEGER, e INTEGER }.
     */
    0x103 : 'ALG_KEY_RSA_2048_PSS_DER'
}


/**
 * Predefined Tags
 * 
 * The internal structure of UAF authenticator commands is a “Tag-Length-Value” (TLV) sequence. The tag is a 2-byte unique unsigned value describing the type of field the data represents, the length is a 2-byte unsigned value indicating the size of the value in bytes, and the value is the variable-sized series of bytes which contain data for this item in the sequence.
 *
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#predefined-tags
 * 
 * type {Object}
 */
var PREDEFINED_TAGS = {
    /* The content of this tag is the authenticator response to a Register command. */
    0x3E01 : 'TAG_UAFV1_REG_ASSERTION',

    /* The content of this tag is the authenticator response to a Sign command. */
    0x3E02 : 'TAG_UAFV1_AUTH_ASSERTION',

    /* Indicates Key Registration Data. */
    0x3E03 : 'TAG_UAFV1_KRD',

    /* Indicates data signed by the authenticator using UAuth.priv key. */
    0x3E04 : 'TAG_UAFV1_SIGNED_DATA',

    /* Indicates DER encoded attestation certificate. */
    0x2E05 : 'TAG_ATTESTATION_CERT',

    /* Indicates a cryptographic signature. */
    0x2E06 : 'TAG_SIGNATURE',

    /* Indicates full basic attestation as defined in [UAFProtocol]. */
    0x3E07 : 'TAG_ATTESTATION_BASIC_FULL',

    /* Indicates surrogate basic attestation as defined in [UAFProtocol]. */
    0x3E08 : 'TAG_ATTESTATION_BASIC_SURROGATE',

    /* Represents a generated KeyID. */
    0x2E09 : 'TAG_KEYID',

    /* Represents an Authenticator Attestation ID as defined in [UAFProtocol]. */
    0x2E0B : 'TAG_AAID',

    /* Represents a generated public key. */
    0x2E0C : 'TAG_PUB_KEY',

    /* Represents the use counters for an authenticator. */
    0x2E0D : 'TAG_COUNTERS',

    /* Represents authenticator information necessary for message processing. */
    0x2E0E : 'TAG_ASSERTION_INFO',

    /* Represents a nonce value generated by the authenticator. */
    0x2E0F : 'TAG_AUTHENTICATOR_NONCE',

    /* Represents a hash of the transaction content sent to the authenticator. */
    0x2E10 : 'TAG_TRANSACTION_CONTENT_HASH',

    /* This is a composite tag indicating that the content is an extension. */
    0x3E11 : 'TAG_EXTENSION',
    0x3E12 : 'TAG_EXTENSION',

    /* Represents extension ID. Content of this tag is a UINT8[] encoding of a UTF-8 string. */
    0x2E13 : 'TAG_EXTENSION_ID',

    /* Represents extension data. Content of this tag is a UINT8[] byte array. */
    0x2E14 : 'TAG_EXTENSION_DATA',

    /* This is the raw UVI as it might be used internally by authenticators. This TAG shall not appear in assertions leaving the authenticator boundary as it could be used as global correlation handle. */
    0x0103 : 'TAG_RAW_USER_VERIFICATION_INDEX',

    /* The user verification index (UVI) is a value uniquely identifying a user verification data record. */
    0x0104 : 'TAG_USER_VERIFICATION_INDEX',

    /* This is the raw UVS as it might be used internally by authenticators. This TAG shall not appear in assertions leaving the authenticator boundary as it could be used as global correlation handle. */
    0x0105 : 'TAG_RAW_USER_VERIFICATION_STATE',

    /* The user verification state (UVS) is a value uniquely identifying the set of active user verification data records. */
    0x0106 : 'TAG_USER_VERIFICATION_STATE',

    /* Reserved for future use. Name of the tag will change, value is fixed. */
    0x0201 : 'TAG_RESERVED_5'
}

var COMMAND_TAGS = {
    /* Tag for GetInfo command. */
    0x3401: 'TAG_UAFV1_GETINFO_CMD',

    /* Tag for GetInfo command response. */
    0x3601: 'TAG_UAFV1_GETINFO_CMD_RESPONSE',

    /* Tag for Register command. */
    0x3402: 'TAG_UAFV1_REGISTER_CMD',

    /* Tag for Register command response. */
    0x3602: 'TAG_UAFV1_REGISTER_CMD_RESPONSE',

    /* Tag for Sign command. */
    0x3403: 'TAG_UAFV1_SIGN_CMD',

    /* Tag for Sign command response. */
    0x3603: 'TAG_UAFV1_SIGN_CMD_RESPONSE',

    /* Tag for Deregister command. */
    0x3404: 'TAG_UAFV1_DEREGISTER_CMD',

    /* Tag for Deregister command response. */
    0x3604: 'TAG_UAFV1_DEREGISTER_CMD_RESPONSE',

    /* Tag for OpenSettings command. */
    0x3406: 'TAG_UAFV1_OPEN_SETTINGS_CMD',

    /* Tag for OpenSettings command response. */
    0x3606: 'TAG_UAFV1_OPEN_SETTINGS_CMD_RESPONSE'
}

var AUTHR_COMMAND_TAGS = {
    /*
     * Represents key handle.
     * Refer to [FIDOGlossary] for more information about key handle.
     */
    0x2801: 'TAG_KEYHANDLE',

    /*
     * Represents an associated Username and key handle.
     * This is a composite tag that contains a TAG_USERNAME and TAG_KEYHANDLE that identify a registration valid oin the authenticator.
     * Refer to [FIDOGlossary] for more information about username.
     */
    0x3802: 'TAG_USERNAME_AND_KEYHANDLE',

    /*
     * Represents a User Verification Token.
     * Refer to [FIDOGlossary] for more information about user verification tokens.
     */
    0x2803: 'TAG_USERVERIFY_TOKEN',

    /*
     * A full AppID as a UINT8[] encoding of a UTF-8 string.
     * Refer to [FIDOGlossary] for more information about AppID.
     */
    0x2804  : 'TAG_APPID',

    /**
     * Represents a key handle Access Token.
     */
    0x2805: 'TAG_KEYHANDLE_ACCESS_TOKEN',

    /**
     * A Username as a UINT8[] encoding of a UTF-8 string.
     */
    0x2806: 'TAG_USERNAME',

    /**
     * Represents an Attestation Type.
     */
    0x2807: 'TAG_ATTESTATION_TYPE',

    /**
     * Represents a Status Code.
     */
    0x2808: 'TAG_STATUS_CODE',

    /**
     * Represents a more detailed set of authenticator information.
     */
    0x2809: 'TAG_AUTHENTICATOR_METADATA',

    /**
     * A UINT8[] containing the UTF8-encoded Assertion Scheme as defined in [UAFRegistry]. ("UAFV1TLV")
     */
    0x280A: 'TAG_ASSERTION_SCHEME',

    /**
     * If an authenticator contains a PNG-capable transaction confirmation display that is not implemented by a higher-level layer, this tag is describing this display. See [UAFAuthnrMetadata] for additional information on the format of this field.
     */
    0x280B: 'TAG_TC_DISPLAY_PNG_CHARACTERISTICS',

    /**
     * A UINT8[] containing the UTF-8-encoded transaction display content type as defined in [UAFAuthnrMetadata]. ("image/png")
     */
    0x280C: 'TAG_TC_DISPLAY_CONTENT_TYPE',

    /**
     * Authenticator Index
     */
    0x280D: 'TAG_AUTHENTICATOR_INDEX',

    /**
     * API Version
     */
    0x280E: 'TAG_API_VERSION',

    /**
     * The content of this TLV tag is an assertion generated by the authenticator. Since authenticators may generate assertions in different formats - the content format may vary from authenticator to authenticator.
     */
    0x280F: 'TAG_AUTHENTICATOR_ASSERTION',

    /**
     * Represents transaction content sent to the authenticator.
     */
    0x2810: 'TAG_TRANSACTION_CONTENT',

    /**
     * Includes detailed information about authenticator's capabilities.
     */
    0x3811: 'TAG_AUTHENTICATOR_INFO',

    /**
     * Represents extension ID supported by authenticator.
     */
    0x2812: 'TAG_SUPPORTED_EXTENSION_ID',

    /* Represents a Final Challenge Hash. */
    0x2E0A: 'TAG_FINAL_CHALLENGE_HASH',

    /* Represents a token for transaction confirmation. It might be returned by the authenticator to the ASM and given back to the authenticator at a later stage. The meaning of it is similar to TAG_USERVERIFY_TOKEN, except that it is used for the user's approval of a displayed transaction text. */
    0x2813: 'TAG_TRANSACTIONCONFIRMATION_TOKEN'
}

var TAG_ASN1_BER = {
    0x1  : 'BOOLEAN',
    0x2  : 'INTEGER',
    0x3  : 'BIT STRING',
    0x4  : 'OCTET STRING',
    0x5  : 'NULL',
    0x6  : 'OBJECT IDENTIFIER',
    0x7  : 'ObjectDescriptor',
    0x8  : 'INSTANCE OF, EXTERNAL',
    0x9  : 'REAL',
    0x10 : 'ENUMERATED',
    0x11 : 'EMBEDDED PDV',
    0x12 : 'UTF8String',
    0x13 : 'RELATIVE-OID',
    0x16 : 'SEQUENCE, SEQUENCE OF',
    0x17 : 'SET, SET OF',
    0x18 : 'NumericString',
    0x19 : 'PrintableString',
    0x20 : 'TeletexString, T61String',
    0x21 : 'VideotexString',
    0x22 : 'IA5String',
    0x23 : 'UTCTime',
    0x24 : 'GeneralizedTime',
    0x25 : 'GraphicString',
    0x26 : 'VisibleString, ISO646String',
    0x27 : 'GeneralString',
    0x28 : 'UniversalString',
    0x29 : 'CHARACTER STRING',
    0x30 : 'BMPString'
}

var TAG_ASN1_DER = {
    0x01 : 'BOOLEAN',
    0x02 : 'INTEGER',
    0x03 : 'BITSTRING',
    0x04 : 'OCTETSTRING',
    0x06 : 'OID',
    0x30 : 'SEQUENCE'
}

var TAG_DIR = {};

/**
 * Merges UAFV1 tags into single object
 */
for (let table of [PREDEFINED_TAGS, COMMAND_TAGS, AUTHR_COMMAND_TAGS])
    for (let key in table)
        TAG_DIR[key] = table[key];


var ALG_DIR = {};

/**
 * Merges UAFV1 Algorithms into single object
 */
for (let table of [AUTHENTICATION_ALGORITHMS, PUBLIC_KEY_REPRESENTATION_FORMATS])
    for (let key in table)
        ALG_DIR[key] = table[key];

var INTERFACE_STATUS_CODES_TO_INT = inverseDictionary(INTERFACE_STATUS_CODES);
var USER_VERIFICATION_METHODS_TO_INT = inverseDictionary(USER_VERIFICATION_METHODS);
var KEY_PROTECTION_TYPES_TO_INT = inverseDictionary(KEY_PROTECTION_TYPES);
var MATCHER_PROTECTION_TYPES_TO_INT = inverseDictionary(MATCHER_PROTECTION_TYPES);
var AUTHENTICATOR_ATTACHMENT_HINTS_TO_INT = inverseDictionary(AUTHENTICATOR_ATTACHMENT_HINTS);
var TRANSACTION_CONFIRMATION_DISPLAY_TYPES_TO_INT = inverseDictionary(TRANSACTION_CONFIRMATION_DISPLAY_TYPES);
var CMD_STATUS_CODES_TO_INT = inverseDictionary(CMD_STATUS_CODES);
var ASM_STATUS_CODES_TO_INT = inverseDictionary(ASM_STATUS_CODES);
var TAG_DIR_TO_INT = inverseDictionary(TAG_DIR);
var ALG_DIR_TO_INT = inverseDictionary(ALG_DIR);

for (let dict of [INTERFACE_STATUS_CODES_TO_INT, USER_VERIFICATION_METHODS_TO_INT, KEY_PROTECTION_TYPES_TO_INT, MATCHER_PROTECTION_TYPES_TO_INT, AUTHENTICATOR_ATTACHMENT_HINTS_TO_INT, TRANSACTION_CONFIRMATION_DISPLAY_TYPES_TO_INT, CMD_STATUS_CODES_TO_INT, ASM_STATUS_CODES_TO_INT, TAG_DIR_TO_INT, ALG_DIR_TO_INT]) {
    for (let key in dict) {
        dict[key] = parseInt(dict[key]);
    }
}