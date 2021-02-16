echo "basicConstraints=CA:FALSE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl genrsa -out RSA.key 2048
openssl req -new -key RSA.key -out RSA.csr -nodes -sha256 -subj "/CN=FIDO2 BATCH KEY RSA/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 3650 -in RSA.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 01 -out RSA.crt -extfile extensionsInfo.cnf


