This folder contains metadata statements for different authenticator types. Here is list of all available authenticators and their AAID.

With attestationTypes: `TAG_ATTESTATION_BASIC_FULL`  `0x3E07` `15879`

 - [x] FFFF#FC01
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW `0x01` `1` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_RAW `0x100` `256`

 - [x] FFFF#FC02
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW `0x01` `1` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_DER `0x101` `257`
    + tcDisplayContentType is image/png

 - [x] FFFF#FC03
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER `0x02` `2` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_RAW `0x100` `256`

 - [x] FFFF#FC04
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER `0x02` `2` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_DER `0x101` `257`
    + tcDisplay is PRIVILEGED_SOFTWARE or 0x00003


 - [x] FFFF#FC05
    + authenticationAlgorithm: UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW `0x03` `3` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_RSA_2048_PSS_RAW `0x102` `258`

 - [x] FFFF#FC06
    + authenticationAlgorithm: UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW `0x03` `3` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_RSA_2048_PSS_DER `0x103` `259`

 - [x] FFFF#FC07
    + authenticationAlgorithm: UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER `0x04` `4` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_RSA_2048_PSS_RAW `0x102` `258`

 - [x] FFFF#FC08
    + authenticationAlgorithm: UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER `0x04` `4` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_RSA_2048_PSS_DER `0x103` `259`

 - [x] FFFF#FC09
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW `0x05` `5` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_RAW `0x100` `256`

 - [x] FFFF#FC0A
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW `0x05` `5` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_DER `0x101` `257`

 - [x] FFFF#FC0B
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER `0x06` `6` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_RAW `0x100` `256`

 - [x] FFFF#FC0C
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER `0x06` `6` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_DER `0x101` `257`


With attestationTypes: `TAG_ATTESTATION_BASIC_SURROGATE` `0x3E08` `15880`

 - [x] FFFF#FC0D
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW `0x01` `1` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_RAW `0x100` `256`


With missing certificate:

 - [x] FFFF#FCFF
    + authenticationAlgorithm: UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW `0x01` `1` 
    + publicKeyAlgAndEncoding: UAF_ALG_KEY_ECC_X962_RAW `0x100` `256`
