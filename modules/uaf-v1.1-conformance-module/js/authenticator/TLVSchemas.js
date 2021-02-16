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
    let REGISTER_CMD_SCHEMA = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_REGISTER_CMD'],
        'fields': {
            'TAG_UAFV1_REGISTER_CMD': {
                'type': 'TLV',
                'order': ['TAG_AUTHENTICATOR_INDEX', 'TAG_APPID', 'TAG_FINAL_CHALLENGE_HASH', 'TAG_USERNAME', 'TAG_ATTESTATION_TYPE', 'TAG_KEYHANDLE_ACCESS_TOKEN', 'TAG_USERVERIFY_TOKEN'],
                'fields': {

                    'TAG_AUTHENTICATOR_INDEX': {
                        'type': 'TLV',
                        'order': ['AuthenticatorIndex'],
                        'fields': {
                            'AuthenticatorIndex': {
                                'type': 'UINT8'
                            }
                        }
                    },
                    'TAG_APPID': {
                        'type': 'TLV',
                        'order': ['AppID'],
                        'fields': {
                            'AppID': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_FINAL_CHALLENGE_HASH': {
                        'type': 'TLV',
                        'order': ['FinalChallenge'],
                        'fields': {
                            'FinalChallenge': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_USERNAME': {
                        'type': 'TLV',
                        'order': ['Username'],
                        'fields': {
                            'Username': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_ATTESTATION_TYPE': {
                        'type': 'TLV',
                        'order': ['AttestationType'],
                        'fields': {
                            'AttestationType': {
                                'type': 'UINT16'
                            }
                        }
                    },
                    'TAG_KEYHANDLE_ACCESS_TOKEN': {
                        'type': 'TLV',
                        'order': ['KHAccessToken'],
                        'fields': {
                            'KHAccessToken': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_USERVERIFY_TOKEN': {
                        'type': 'TLV',
                        'optional': true,
                        'order': ['VerificationToken'],
                        'fields': {
                            'VerificationToken': {
                                'type': 'UINT8 []'
                            }
                        }
                    }
                }
            }
        }
    }

    let REGISTER_CMD_RESPONSE_SCHEMA = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_REGISTER_CMD_RESPONSE'],
        'fields': {
            'TAG_UAFV1_REGISTER_CMD_RESPONSE': {
                'type': 'TLV',
                'order': ['TAG_STATUS_CODE', 'TAG_AUTHENTICATOR_ASSERTION', 'TAG_KEYHANDLE'],
                'fields': {
                    'TAG_STATUS_CODE': {
                        'type': 'TLV',
                        'order': ['StatusCode'],
                        'fields': {
                            'StatusCode': {
                                'type': 'UINT16'
                            }
                        }
                    },
                    'TAG_AUTHENTICATOR_ASSERTION': {
                        'type': 'TLV',
                        'order': ['Assertion'],
                        'fields': {
                            'Assertion': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_KEYHANDLE': {
                        'type': 'TLV',
                        'order': ['KeyHandle'],
                        'optional': true,
                        'fields': {
                            'KeyHandle': {
                                'type': 'UINT8 []'
                            }
                        }
                    }
                }
            }
        }
    }

    let REGISTER_ASSERTION_SCHEMA_KRD = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_KRD'],
        'fields': {
            'TAG_UAFV1_KRD': {
                'type': 'TLV',
                'order': ['TAG_AAID', 'TAG_ASSERTION_INFO', 'TAG_FINAL_CHALLENGE_HASH', 'TAG_KEYID', 'TAG_COUNTERS', 'TAG_PUB_KEY'],
                'fields': {
                    'TAG_AAID': {
                        'type': 'TLV',
                        'order': ['AAID'],
                        'fields': {
                            'AAID': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_ASSERTION_INFO': {
                        'type': 'TLV',
                        'order': ['AuthenticatorVersion', 'AuthenticationMode', 'SignatureAlgAndEncoding', 'PublicKeyAlgAndEncoding'],
                        'fields': {
                            'AuthenticatorVersion': {
                                'type': 'UINT16'
                            },
                            'AuthenticationMode': {
                                'type': 'UINT8'
                            },
                            'SignatureAlgAndEncoding': {
                                'type': 'UINT16'
                            },
                            'PublicKeyAlgAndEncoding': {
                                'type': 'UINT16'
                            }

                        }
                    },
                    'TAG_FINAL_CHALLENGE_HASH': {
                        'type': 'TLV',
                        'order': ['FinalChallenge'],
                        'fields': {
                            'FinalChallenge': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_KEYID': {
                        'type': 'TLV',
                        'order': ['KeyID'],
                        'fields': {
                            'KeyID': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_COUNTERS': {
                        'type': 'TLV',
                        'order': ['SignCounter', 'RegCounter'],
                        'fields': {
                            'SignCounter': {
                                'type': 'UINT32'
                            },
                            'RegCounter': {
                                'type': 'UINT32'
                            }

                        }
                    },
                    'TAG_PUB_KEY': {
                        'type': 'TLV',
                        'order': ['PublicKey'],
                        'fields': {
                            'PublicKey': {
                                'type': 'UINT8 []'
                            }
                        }
                    }
                }
            }
        }
    }

    let REGISTER_ASSERTION_SCHEMA = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_REG_ASSERTION'],
        'fields': {
            'TAG_UAFV1_REG_ASSERTION': {
                'type': 'TLV',
                'order': ['TAG_UAFV1_KRD', 'TAG_ATTESTATION_BASIC_FULL', 'TAG_ATTESTATION_BASIC_SURROGATE'],
                'fields': {
                    'TAG_UAFV1_KRD': {
                        'type': 'TLV',
                        'order': ['TAG_AAID', 'TAG_ASSERTION_INFO', 'TAG_FINAL_CHALLENGE_HASH', 'TAG_KEYID', 'TAG_COUNTERS', 'TAG_PUB_KEY'],
                        'fields': {
                            'TAG_AAID': {
                                'type': 'TLV',
                                'order': ['AAID'],
                                'fields': {
                                    'AAID': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_ASSERTION_INFO': {
                                'type': 'TLV',
                                'order': ['AuthenticatorVersion', 'AuthenticationMode', 'SignatureAlgAndEncoding', 'PublicKeyAlgAndEncoding'],
                                'fields': {
                                    'AuthenticatorVersion': {
                                        'type': 'UINT16'
                                    },
                                    'AuthenticationMode': {
                                        'type': 'UINT8'
                                    },
                                    'SignatureAlgAndEncoding': {
                                        'type': 'UINT16'
                                    },
                                    'PublicKeyAlgAndEncoding': {
                                        'type': 'UINT16'
                                    }

                                }
                            },
                            'TAG_FINAL_CHALLENGE_HASH': {
                                'type': 'TLV',
                                'order': ['FinalChallenge'],
                                'fields': {
                                    'FinalChallenge': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_KEYID': {
                                'type': 'TLV',
                                'order': ['KeyID'],
                                'fields': {
                                    'KeyID': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_COUNTERS': {
                                'type': 'TLV',
                                'order': ['SignCounter', 'RegCounter'],
                                'fields': {
                                    'SignCounter': {
                                        'type': 'UINT32'
                                    },
                                    'RegCounter': {
                                        'type': 'UINT32'
                                    }

                                }
                            },
                            'TAG_PUB_KEY': {
                                'type': 'TLV',
                                'order': ['PublicKey'],
                                'fields': {
                                    'PublicKey': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            }
                        }
                    },
                    'TAG_ATTESTATION_BASIC_FULL': {
                        'type': 'TLV',
                        'order': ['TAG_SIGNATURE', 'TAG_ATTESTATION_CERT'],
                        'optional': true,
                        'fields': {
                            'TAG_SIGNATURE': {
                                'type': 'TLV',
                                'order': ['Signature'],
                                'fields': {
                                    'Signature': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_ATTESTATION_CERT': {
                                'type': 'TLV',
                                'order': ['Certificate'],
                                'fields': {
                                    'Certificate': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            }
                        }

                    },
                    'TAG_ATTESTATION_BASIC_SURROGATE': {
                        'type': 'TLV',
                        'order': ['TAG_SIGNATURE'],
                        'optional': true,
                        'fields': {
                            'TAG_SIGNATURE': {
                                'type': 'TLV',
                                'order': ['Signature'],
                                'fields': {
                                    'Signature': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

/* ----- SIGN ----- */
    let SIGN_CMD_SCHEMA = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_SIGN_CMD'],
        'fields': {
            'TAG_UAFV1_SIGN_CMD': {
                'type': 'TLV',
                'order': ['TAG_AUTHENTICATOR_INDEX', 'TAG_APPID', 'TAG_FINAL_CHALLENGE_HASH', 'TAG_TRANSACTION_CONTENT', 'TAG_KEYHANDLE_ACCESS_TOKEN', 'TAG_USERVERIFY_TOKEN', 'TAG_KEYHANDLE'],
                'fields': {
                    'TAG_AUTHENTICATOR_INDEX': {
                        'type': 'TLV',
                        'order': ['AuthenticatorIndex'],
                        'fields': {
                            'AuthenticatorIndex': {
                                'type': 'UINT8'
                            }
                        }
                    },
                    'TAG_APPID': {
                        'type': 'TLV',
                        'order': ['AppID'],
                        'optional': true,
                        'fields': {
                            'AppID': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_FINAL_CHALLENGE_HASH': {
                        'type': 'TLV',
                        'order': ['FinalChallenge'],
                        'fields': {
                            'FinalChallenge': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_TRANSACTION_CONTENT': {
                        'type': 'TLV',
                        'order': ['TransactionContent'],
                        'optional': true,
                        'fields': {
                            'TransactionContent': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_KEYHANDLE_ACCESS_TOKEN': {
                        'type': 'TLV',
                        'order': ['KHAccessToken'],
                        'fields': {
                            'KHAccessToken': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_USERVERIFY_TOKEN': {
                        'type': 'TLV',
                        'order': ['VerificationToken'],
                        'optional': true,
                        'fields': {
                            'VerificationToken': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_KEYHANDLE': {
                        'type': 'TLV',
                        'order': ['KeyHandle'],
                        'optional': true,
                        'fields': {
                            'KeyHandle': {
                                'type': 'UINT8 []'
                            }
                        }
                    }
                }
            }
        }
    }

    let SIGN_CMD_RESPONSE_SCHEMA = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_SIGN_CMD_RESPONSE'],
        'fields': {
            'TAG_UAFV1_SIGN_CMD_RESPONSE': {
                'type': 'TLV',
                'order': ['TAG_STATUS_CODE', 'TAG_USERNAME_AND_KEYHANDLE', 'TAG_AUTHENTICATOR_ASSERTION'],
                'fields': {
                    'TAG_STATUS_CODE': {
                        'type': 'TLV',
                        'order': ['StatusCode'],
                        'fields': {
                            'StatusCode': {
                                'type': 'UINT16'
                            }
                        }
                    },
                    'TAG_USERNAME_AND_KEYHANDLE': {
                        'type': 'TLV',
                        'order': ['TAG_USERNAME', 'TAG_KEYHANDLE'],
                        'optional': true,
                        'fields': {
                            'TAG_USERNAME': {
                                'type': 'TLV',
                                'order': ['Username'],
                                'fields': {
                                    'Username': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_KEYHANDLE': {
                                'type': 'TLV',
                                'order': ['KeyHandle'],
                                'fields': {
                                    'KeyHandle': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            }

                        }
                    },
                    'TAG_AUTHENTICATOR_ASSERTION': {
                        'type': 'TLV',
                        'order': ['Assertion'],
                        'optional': true,
                        'fields': {
                            'Assertion': {
                                'type': 'UINT8 []'
                            }
                        }
                    }
                }
            }
        }
    }

    let SIGN_ASSERTION_SCHEMA = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_AUTH_ASSERTION'],
        'fields': {
            'TAG_UAFV1_AUTH_ASSERTION': {
                'type': 'TLV',
                'order': ['TAG_UAFV1_SIGNED_DATA', 'TAG_SIGNATURE'],
                'fields': {
                    'TAG_UAFV1_SIGNED_DATA': {
                        'type': 'TLV',
                        'order': ['TAG_AAID', 'TAG_ASSERTION_INFO', 'TAG_AUTHENTICATOR_NONCE', 'TAG_FINAL_CHALLENGE_HASH', 'TAG_TRANSACTION_CONTENT_HASH', 'TAG_KEYID', 'TAG_COUNTERS'],
                        'fields': {
                            'TAG_AAID': {
                                'type': 'TLV',
                                'order': ['AAID'],
                                'fields': {
                                    'AAID': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_ASSERTION_INFO': {
                                'type': 'TLV',
                                'order': ['AuthenticatorVersion', 'AuthenticationMode', 'SignatureAlgAndEncoding'],
                                'fields': {
                                    'AuthenticatorVersion': {
                                        'type': 'UINT16'
                                    },
                                    'AuthenticationMode': {
                                        'type': 'UINT8'
                                    },
                                    'SignatureAlgAndEncoding': {
                                        'type': 'UINT16'
                                    }
                                }
                            },
                            'TAG_AUTHENTICATOR_NONCE': {
                                'type': 'TLV',
                                'order': ['AuthrNonce'],
                                'fields': {
                                    'AuthrNonce': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_FINAL_CHALLENGE_HASH': {
                                'type': 'TLV',
                                'order': ['FinalChallenge'],
                                'fields': {
                                    'FinalChallenge': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_TRANSACTION_CONTENT_HASH': {
                                'type': 'TLV',
                                'order': ['TCHash'],
                                'optional': true,
                                'fields': {
                                    'TCHash': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_TRANSACTION_CONTENT': {
                                'type': 'TLV',
                                'order': ['TransactionContent'],
                                'optional': true,
                                'fields': {
                                    'TransactionContent': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_KEYID': {
                                'type': 'TLV',
                                'order': ['KeyID'],
                                'fields': {
                                    'KeyID': {
                                        'type': 'UINT8 []'
                                    }
                                }
                            },
                            'TAG_COUNTERS': {
                                'type': 'TLV',
                                'order': ['SignCounter'],
                                'fields': {
                                    'SignCounter': {
                                        'type': 'UINT32'
                                    }
                                }
                            }
                        }
                    },
                    'TAG_SIGNATURE': {
                        'type': 'TLV',
                        'order': ['Signature'],
                        'fields': {
                            'Signature': {
                                'type': 'UINT8 []'
                            }
                        }
                    }
                }
            }
        }
    }

    let SIGN_ASSERTION_SCHEMA_SIGNED_DATA = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_SIGNED_DATA'],
        'fields': {
            'TAG_UAFV1_SIGNED_DATA': {
                'type': 'TLV',
                'order': ['TAG_AAID', 'TAG_ASSERTION_INFO', 'TAG_AUTHENTICATOR_NONCE', 'TAG_FINAL_CHALLENGE_HASH', 'TAG_TRANSACTION_CONTENT_HASH', 'TAG_KEYID', 'TAG_COUNTERS'],
                'fields': {
                    'TAG_AAID': {
                        'type': 'TLV',
                        'order': ['AAID'],
                        'fields': {
                            'AAID': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_ASSERTION_INFO': {
                        'type': 'TLV',
                        'order': ['AuthenticatorVersion', 'AuthenticationMode', 'SignatureAlgAndEncoding'],
                        'fields': {
                            'AuthenticatorVersion': {
                                'type': 'UINT16'
                            },
                            'AuthenticationMode': {
                                'type': 'UINT8'
                            },
                            'SignatureAlgAndEncoding': {
                                'type': 'UINT16'
                            }
                        }
                    },
                    'TAG_AUTHENTICATOR_NONCE': {
                        'type': 'TLV',
                        'order': ['AuthrNonce'],
                        'fields': {
                            'AuthrNonce': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_FINAL_CHALLENGE_HASH': {
                        'type': 'TLV',
                        'order': ['FinalChallenge'],
                        'fields': {
                            'FinalChallenge': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_TRANSACTION_CONTENT_HASH': {
                        'type': 'TLV',
                        'order': ['TCHash'],
                        'fields': {
                            'TCHash': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_KEYID': {
                        'type': 'TLV',
                        'order': ['KeyID'],
                        'fields': {
                            'KeyID': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_COUNTERS': {
                        'type': 'TLV',
                        'order': ['SignCounter'],
                        'fields': {
                            'SignCounter': {
                                'type': 'UINT32'
                            }
                        }
                    }
                }
            }
        }
    }

/* ----- DEREGISTRATION ----- */
    let DEREGISTER_CMD_SCHEMA = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_DEREGISTER_CMD'],
        'fields': {
            'TAG_UAFV1_DEREGISTER_CMD': {
                'type': 'TLV',
                'order': ['TAG_AUTHENTICATOR_INDEX', 'TAG_APPID', 'TAG_KEYID', 'TAG_KEYHANDLE_ACCESS_TOKEN'],
                'fields': {
                    'TAG_AUTHENTICATOR_INDEX': {
                        'type': 'TLV',
                        'order': ['AuthenticatorIndex'],
                        'fields': {
                            'AuthenticatorIndex': {
                                'type': 'UINT8'
                            }
                        }
                    },
                    'TAG_APPID': {
                        'type': 'TLV',
                        'order': ['AppID'],
                        'optional': true,
                        'fields': {
                            'AppID': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_KEYID': {
                        'type': 'TLV',
                        'order': ['KeyID'],
                        'fields': {
                            'KeyID': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    'TAG_KEYHANDLE_ACCESS_TOKEN': {
                        'type': 'TLV',
                        'order': ['KHAccessToken'],
                        'fields': {
                            'KHAccessToken': {
                                'type': 'UINT8 []'
                            }
                        }
                    },
                    
                }
            }
        }
    }

    let DEREGISTER_CMD_RESPONSE_SCHEMA = {
        'type': 'TLV',
        'order': ['TAG_UAFV1_DEREGISTER_CMD_RESPONSE'],
        'fields': {
            'TAG_UAFV1_DEREGISTER_CMD_RESPONSE': {
                'type': 'TLV',
                'order': ['TAG_STATUS_CODE'],
                'fields': {
                    'TAG_STATUS_CODE': {
                        'type': 'TLV',
                        'order': ['StatusCode'],
                        'fields': {
                            'StatusCode': {
                                'type': 'UINT16'
                            }
                        }
                    }
                }
            }
        }
    }

    /* TODO: Add deep freezing */
    window.UAF.TLVSchemas = Object.freeze({
        REGISTER_CMD_SCHEMA,
        REGISTER_CMD_RESPONSE_SCHEMA,
        REGISTER_ASSERTION_SCHEMA,
        REGISTER_ASSERTION_SCHEMA_KRD,
        SIGN_CMD_SCHEMA,
        SIGN_CMD_RESPONSE_SCHEMA,
        SIGN_ASSERTION_SCHEMA,
        SIGN_ASSERTION_SCHEMA_SIGNED_DATA,
        DEREGISTER_CMD_SCHEMA,
        DEREGISTER_CMD_RESPONSE_SCHEMA
    })

})()
