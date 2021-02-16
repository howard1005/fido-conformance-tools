echo "basicConstraints=CA:FALSE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name secp256k1 -out secp256k1.param
openssl ecparam -in secp256k1.param -genkey -noout -out secp256k1.key
openssl req -new -key secp256k1.key -out secp256k1.csr -nodes -sha256 -subj "/CN=FIDO2 BATCH KEY secp256k1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 3650 -in secp256k1.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 01 -out secp256k1.crt -extfile extensionsInfo.cnf