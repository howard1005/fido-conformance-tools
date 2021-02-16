openssl ecparam -name prime256v1 -out prime256v1ExpiredIntermediate.param
openssl ecparam -in prime256v1ExpiredIntermediate.param -genkey -noout -out prime256v1ExpiredIntermediate.key
openssl req -new -key prime256v1ExpiredIntermediate.key -out prime256v1ExpiredIntermediate.csr -nodes -sha256 -subj "/CN=FIDO2 INTERMEDIATE prime256v1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=CWG/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 1 -in prime256v1ExpiredIntermediate.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 02 -out prime256v1ExpiredIntermediate.crt

echo "basicConstraints=CA:FALSE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name prime256v1 -out prime256v1ForExpiredIntermediate.param
openssl ecparam -in prime256v1ForExpiredIntermediate.param -genkey -noout -out prime256v1ForExpiredIntermediate.key
openssl req -new -key prime256v1ForExpiredIntermediate.key -out prime256v1ForExpiredIntermediate.csr -nodes -sha256 -subj "/CN=FIDO2 BATCH KEY prime256v1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 3650 -in prime256v1ForExpiredIntermediate.csr -CA prime256v1ExpiredIntermediate.crt -CAkey prime256v1ExpiredIntermediate.key -set_serial 01 -out prime256v1ForExpiredIntermediate.crt -extfile extensionsInfo.cnf
