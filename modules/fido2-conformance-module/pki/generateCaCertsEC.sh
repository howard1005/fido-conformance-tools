openssl ecparam -name secp256k1 -out TROOTEC.param
openssl req -x509 -nodes -days 10000 -newkey ec:TROOTEC.param -keyout TROOTEC.key -out TROOTEC.crt -subj "/CN=FIDO2 TEST ROOT EC/emailAddress=conformance-tools@fidoalliance.org/O=CWG/OU=Authenticator Attestation/C=US/ST=MY/L=Wakefield"
