echo "basicConstraints=CA:FALSE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name prime256v1 -out prime256v1.param
openssl ecparam -in prime256v1.param -genkey -noout -out prime256v1.key
openssl req -new -key prime256v1.key -out prime256v1.csr -nodes -sha256 -subj "/CN=FIDO2 BATCH KEY prime256v1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 3650 -in prime256v1.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 01 -out prime256v1.crt -extfile extensionsInfo.cnf