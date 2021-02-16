echo "basicConstraints=CA:FALSE
subjectKeyIdentifier = hash" > extensionsInfo.cnf

openssl ecparam -name secp521r1 -out secp521r1.param
openssl ecparam -in secp521r1.param -genkey -noout -out secp521r1.key
openssl req -new -key secp521r1.key -out secp521r1.csr -nodes -sha512 -subj "/CN=FIDO2 BATCH KEY secp521r1/emailAddress=conformance-tools@fidoalliance.org/O=FIDO Alliance/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
openssl x509 -req -days 3650 -in secp521r1.csr -CA TROOT.crt -CAkey TROOT.key -set_serial 01 -out secp521r1.crt -extfile extensionsInfo.cnf