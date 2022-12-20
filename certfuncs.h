#ifndef __CERT_FUNC_H__
#define __CERT_FUNC_H__

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>

#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/dh.h>


#include <memory>
#include <string>

// inline helper functions
inline void help_openssl_free_char(char* p) { OPENSSL_free(p); }
inline void help_openssl_free_uchar(unsigned char* p) { OPENSSL_free(p); }


// curve to use
const int nid = NID_secp384r1;
//const int nid = NID_secp256k1; 

using ocsp_ptr = std::unique_ptr<OCSP_REQUEST, decltype(&OCSP_REQUEST_free)>; 
using file_ptr = std::unique_ptr<FILE, int(*)(FILE*)>; 
using x509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using x509_req_ptr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
using x509_name_ptr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;

using bio_mem_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;

// added types for loading private keys
using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using rsa_key_ptr = std::unique_ptr<RSA, decltype(&RSA_free)>;
using bn_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
// For EC keys
using EC_KEY_ptr = std::unique_ptr< EC_KEY, decltype(&EC_KEY_free)   >; 
using STR_ptr = std::unique_ptr<char, decltype(&help_openssl_free_char)>;//
using BN_CTX_ptr = std::unique_ptr< BN_CTX, decltype(&BN_CTX_free) >;
using EC_GROUP_ptr = std::unique_ptr< EC_GROUP, decltype(&EC_GROUP_free) >;
using EC_POINT_ptr = std::unique_ptr< EC_POINT, decltype(&EC_POINT_free) >;

// For DH 
using DH_ptr = std::unique_ptr<DH, decltype(&DH_free)> ; 

std::string asn1int(ASN1_INTEGER *);
std::string CertSerialNumber(const x509_ptr&);
std::string pem(const x509_ptr&);
std::string PubkeyStr(const evp_pkey_ptr&); 

// OCSP functions
bool OCSP_Verify(const x509_ptr&, const x509_ptr&);

// private key functions
bool LoadPriKeyFromFile(const std::string&, evp_pkey_ptr&);
bool WritePriKeyToFile(const std::string&, const evp_pkey_ptr&);
evp_pkey_ptr CreateRSAkey ();

// public key functions
bool WritePubKeyToFile(const std::string&, const evp_pkey_ptr&); 
bool LoadPubKeyfromFile(const std::string&, evp_pkey_ptr&); 


// EC Key functions
EC_KEY_ptr CreateECPrivateKey();
EC_KEY_ptr CreateECPrivateKeyFromSharedSecert(const std::string&); 

std::string GetPublicKeyHexString(const EC_KEY_ptr&); 
bool WriteECPrivateKey(const std::string&, const EC_KEY_ptr&);
bool LoadECPrivateKeyFromFile(const std::string&, EC_KEY_ptr&);

// x509 functions
bool LoadX509FromFile(const std::string, x509_ptr&);
bool LoadX09CSRFromFile(const std::string&, x509_req_ptr&);
std::string PubKeyPemFromCert(const x509_ptr&);
bool IsTempX509(const x509_ptr&); 
std::unique_ptr<unsigned char[]> X509_TBS(const x509_ptr&, int&);
x509_ptr CreateFromCSR(const x509_req_ptr&, const std::string&);
bool WriteX509Cert(const x509_ptr&, const std::string&);

// CSR functions
x509_req_ptr generate_cert_req(const std::string&, const std::string&);
bool WriteCSR(const x509_req_ptr&, const std::string&); 

// X509 Name structure 
x509_name_ptr CreateSubject(const std::string&, const std::string&, const std::string&, 
                            const std::string&, const std::string&, const std::string&);
// Secret Sharing
std::string CreateSecret(const std::string&, const EC_KEY_ptr&);
#endif //#ifndef __CERT_FUNC_H__