echo "basicConstraints=CA:FALSE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name prime256v1 -out prime256v1NOTSTARTEDYET.param
openssl ecparam -in prime256v1NOTSTARTEDYET.param -genkey -noout -out prime256v1NOTSTARTEDYET.key
openssl req -new -key prime256v1NOTSTARTEDYET.key -out prime256v1NOTSTARTEDYET.csr -nodes -sha256 -subj "/CN=FIDO2 NOTSTARTEDYET BATCH KEY prime256v1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 3650 -in prime256v1NOTSTARTEDYET.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 01 -out prime256v1NOTSTARTEDYET.crt -extfile extensionsInfo.cnf