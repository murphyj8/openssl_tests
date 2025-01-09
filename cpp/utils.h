#ifndef __UTILS_H__
#define __UTILS_H__

#include <iostream>
#include <openssl/x509.h>

#include <openssl/pem.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>


#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>


using x509_ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using bio_mem_ptr       = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using file_ptr          = std::unique_ptr<FILE, decltype(&::fclose)>;
using x509_req_ptr      = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
using pkey_ptr          = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using ASN1_INTEGER_ptr  = std::unique_ptr<ASN1_INTEGER, decltype(&::ASN1_INTEGER_free)>;
using ASN1_OCTET_ptr    = std::unique_ptr<ASN1_OCTET_STRING, decltype(&::ASN1_OCTET_STRING_free)>;
using SIG_ptr           = std::unique_ptr< ECDSA_SIG, decltype(&ECDSA_SIG_free)>;
using BN_ptr            = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using EC_GROUP_ptr      = std::unique_ptr< EC_GROUP, decltype(&EC_GROUP_free) >;


void print_x509_sig(X509* cert);

x509_ptr template_x509( const std::string& country, 
                        const std::string& organisation,
                        const std::string& common_name,
                        unsigned int validity,
                        pkey_ptr& temporary_key,
                        const std::string& groupID) ;

x509_ptr template_client_x509( 
                        const x509_ptr& ca_cert,
                        const x509_req_ptr& csr_ptr,
                        unsigned int validity,
                        pkey_ptr& temporary_key,
                        const std::string& groupID);

pkey_ptr load_private_key(const std::string& filename);

x509_req_ptr load_csr(const std::string& filename);

x509_ptr load_ca(const std::string& ca_cert_file);

int verify_csr_signature(const x509_req_ptr& csr_req_ptr);

void init_openssl();

std::unique_ptr<unsigned char[]> 
    raw_to_DER_signature(   size_t& len, 
                            const std::string& sigr,
                            const std::string& sigs ) ;

std::string binTohexStr(const std::unique_ptr<unsigned char[]>& data, int len);


pkey_ptr  convertPubKeyStrToEVP( const std::string& the_key, int curve_id ) ;

std::unique_ptr<unsigned char[]> X509_TBS(const x509_ptr&, int&);

std::unique_ptr<unsigned char []> HashIt(const std::unique_ptr<unsigned char[]>& msg, const int& len, int& digestlen);
 
std::unique_ptr<unsigned char[]> HexStrToBin(const std::string& input, size_t *l);

pkey_ptr createNewKey(int curve_id) ;

int getCurveNidFromCert(const x509_ptr& cert);


#endif //#ifndef __UTILS_H__
