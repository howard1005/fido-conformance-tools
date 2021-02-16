echo "
[ req ]
default_bits = 4096
default_keyfile = TPMROOT.key
encrypt_key = no
default_md = sha256
prompt = no
utf8 = yes
distinguished_name = my_req_distinguished_name
x509_extensions = ca

[ my_req_distinguished_name ]
C = US
ST = MY
L = Wakefield
O  = FIDO Alliance
OU = CWG
CN = FIDO Fake TPM Root Certificate Authority 2018
emailAddress = conformance-tools@fidoalliance.org

[ ca ]
basicConstraints       = critical,CA:TRUE
keyUsage               = critical,digitalSignature,keyCertSign
subjectKeyIdentifier   = hash

" > TPMCACreation.conf

openssl req -new -newkey rsa:4096 -x509 -sha256 -days 10000 -nodes -out TPMROOT.crt -keyout TPMROOT.key -config TPMCACreation.conf
# openssl req -new -key TPMROOT.key -x509 -sha256 -days 10000 -nodes -out TPMROOT.crt -config TPMCACreation.conf #For regeneration