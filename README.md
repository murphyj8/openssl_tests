# openssl_tests
testing ground for various openssl stuff

The first test is take a hex representation of a public key (compressed), add it to an x509 certificate, extract it from the certificate 
and verify that it's the same value. 

# To build the project
g++ -Wall -I. -I/usr/local/include curlfuncs.cc certfuncs.cc test_pub_key.cc -o test_pub_key -L/usr/local/lib -lssl -lcrypto -lcurl -std=c++17

g++ -Wall -I. -I/usr/local/include curlfuncs.cc certfuncs.cc cert_gen_signing.cc -o cert_gen_signing -L/usr/local/lib -lssl -lcrypto -lcurl -std=c++17

# Useful openssl commands for a CSR request

## dump the CSR request
```bash
openssl req -in <FILENAME> -text -noout
```

## verify the CSR request
```bash
openssl req -in <FILENAME> -noout -verify
```

## show the subject 
```bash
openssl req -in <FILENAME> -noout -subject
```

## Show the public key
```bash
openssl req -in <FILENAME> -noout -pubkey
```

# Useful openssl commands for generating private keys
```bash
openssl ecparam -name secp384r1 -genkey -noout -out ec-secp384r1-priv-key.pem
```

## Generate a CSR on the commandline
```bash
openssl req -new -key ec-secp384r1-priv-key.pem -out server.csr
openssl req -new -nodes -sha256  -key ec-secp384r1-priv-key.pem -out example.com.csr -subj "/emailAddress=j.murphy@nchain.com/CN=example-cert.com/O=nChain/OU=Research/C=UK/ST=Greater London/L=Oxford Street"
```


