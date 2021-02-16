echo "basicConstraints=CA:FALSE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name secp384r1 -out secp384r1.param
openssl ecparam -in secp384r1.param -genkey -noout -out secp384r1.key
openssl req -new -key secp384r1.key -out secp384r1.csr -nodes -sha384 -subj "/CN=FIDO2 BATCH KEY secp384r1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 3650 -in secp384r1.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 01 -out secp384r1.crt -extfile extensionsInfo.cnf