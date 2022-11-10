# openssl_tests
testing ground for various openssl stuff

The first test is take a hex representation of a public key (compressed), add it to an x509 certificate, extract it from the certificate 
and verify that it's the same value. 

# To build the project
g++ -Wall -I. -I/usr/local/include curlfuncs.cc certfuncs.cc test_pub_key.cc -o test_pub_key -L/usr/local/lib -lssl -lcrypto -lcurl -std=c++17


