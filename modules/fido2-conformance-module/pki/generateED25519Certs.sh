echo "basicConstraints=CA:FALSE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name ed25519 -out ed25519.param
openssl ecparam -in ed25519.param -genkey -noout -out ed25519.key
openssl req -new -key ed25519.key -out ed25519.csr -nodes -sha256 -subj "/CN=FIDO2 BATCH KEY ed25519/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 3650 -in ed25519.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 01 -out ed25519.crt -extfile extensionsInfo.cnf