echo "[ ca ]
basicConstraints       = critical,CA:TRUE
keyUsage               = critical,digitalSignature,keyCertSign
subjectKeyIdentifier   = hash  
authorityKeyIdentifier = keyid:always" > extensionsInfo.cnf

openssl ecparam -name prime256v1 -out FATROOT.param
openssl ecparam -in FATROOT.param -genkey -noout -out FATROOT.key
openssl req -new -key FATROOT.key -out FATROOT.csr -nodes -sha256 -subj "/CN=FAKE Android Keystore Software Attestation Root FAKE/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -sha256 -extfile extensionsInfo.cnf -extensions ca -in FATROOT.csr -signkey FATROOT.key -days 20000 -out FATROOT.crt

openssl ecparam -name prime256v1 -out FATINTERMEDIATE.param
openssl ecparam -in FATINTERMEDIATE.param -genkey -noout -out FATINTERMEDIATE.key
openssl req -new -key FATINTERMEDIATE.key -out FATINTERMEDIATE.csr -nodes -sha256 -subj "/CN=FAKE Android Keystore Software Attestation Intermediate FAKE/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -sha256 -extfile extensionsInfo.cnf -extensions ca -days 10000 -in FATINTERMEDIATE.csr -CA FATROOT.crt -CAkey FATROOT.key -set_serial 02 -out FATINTERMEDIATE.crt