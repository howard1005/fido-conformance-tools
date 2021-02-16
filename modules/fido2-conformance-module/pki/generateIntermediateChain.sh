echo "basicConstraints=CA:TRUE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name prime256v1 -out prime256v1Intermediate.param
openssl ecparam -in prime256v1Intermediate.param -genkey -noout -out prime256v1Intermediate.key
openssl req -new -key prime256v1Intermediate.key -out prime256v1Intermediate.csr -nodes -sha256 -subj "/CN=FIDO2 INTERMEDIATE prime256v1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=CWG/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 10000 -in prime256v1Intermediate.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 02 -out prime256v1Intermediate.crt -extfile extensionsInfo.cnf


echo "basicConstraints=CA:FALSE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name prime256v1 -out prime256v1ForIntermediate.param
openssl ecparam -in prime256v1ForIntermediate.param -genkey -noout -out prime256v1ForIntermediate.key
openssl req -new -key prime256v1ForIntermediate.key -out prime256v1ForIntermediate.csr -nodes -sha256 -subj "/CN=FIDO2 BATCH KEY prime256v1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 3650 -in prime256v1ForIntermediate.csr -CA prime256v1Intermediate.crt -CAkey prime256v1Intermediate.key -set_serial 01 -out prime256v1ForIntermediate.crt -extfile extensionsInfo.cnf
