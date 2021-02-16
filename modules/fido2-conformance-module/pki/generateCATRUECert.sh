echo "basicConstraints=CA:TRUE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name prime256v1 -out prime256v1CATRUE.param
openssl ecparam -in prime256v1CATRUE.param -genkey -noout -out prime256v1CATRUE.key
openssl req -new -key prime256v1CATRUE.key -out prime256v1CATRUE.csr -nodes -sha256 -subj "/CN=FIDO2 CATRUE prime256v1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 1 -in prime256v1CATRUE.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 01 -out prime256v1CATRUE.crt -extfile extensionsInfo.cnf