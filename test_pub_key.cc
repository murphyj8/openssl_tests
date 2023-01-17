#include <iostream>
#include <cassert>

#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/ec.h>

#include <openssl/evp.h>

#include "certfuncs.h"

int main(int argc, char* argv[]){
    std::cout << "Starting" << std::endl; 
    EC_GROUP * m_gp = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_POINT * m_ec = EC_POINT_new(m_gp);

    EC_KEY_ptr priv_key = CreateECPrivateKey();

    std::string hexStr = GetPublicKeyHexString(priv_key); 
    std::cout << hexStr<< std::endl; 

    // Allocate for CTX
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    assert(ctxptr != nullptr);


    m_ec = EC_POINT_hex2point(m_gp, hexStr.c_str(), m_ec, ctxptr.get());
    assert(m_ec != nullptr);


    // create a new EC KEY & assign the point to the public key. 
    EC_KEY_ptr ec_key (EC_KEY_new(), &EC_KEY_free); 
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_KEY_set_group(ec_key.get(), ec_group);
    EC_KEY_set_asn1_flag(ec_key.get(), OPENSSL_EC_NAMED_CURVE);
    if(EC_KEY_set_public_key(ec_key.get(), m_ec) <= 0){
        std::cout << "Could not assign pub key" << std::endl;
        return -1;
    }

    EVP_PKEY * pkey = EVP_PKEY_new(); 
    assert(pkey != nullptr);

    if(EVP_PKEY_assign_EC_KEY(pkey, ec_key.get()) <= 0){
        std::cout << "Failure to asign to PK" << std::endl; 
        return -1; 
    }

    // create the x509
    x509_ptr x_ptr (X509_new(), &X509_free);
    assert(x_ptr != nullptr);

    if(X509_set_pubkey(x_ptr.get(),  pkey) != 1){
        std::cout << "Could not set x509 public key...panic" << std::endl; 
        return -1; 
    }

    std::cout << "Public key from cert -> " << PubKeyPemFromCert(x_ptr) << std::endl; 

    // load the PEM format & compare to the original & then we are done. 
    evp_pkey_ptr pubkey_ptr (X509_get_pubkey(x_ptr.get()), &EVP_PKEY_free); 
    if(!pubkey_ptr){
        std::cout << "panic retriving public key from cert" << std::endl; 
        return 1; 
    }
    //back to an ec key
    const EC_KEY * ec_tmp_ptr = EVP_PKEY_get0_EC_KEY(pubkey_ptr.get());
    assert(ec_tmp_ptr != nullptr);

    // back to an EC-point
    const EC_POINT * ec_point_pk = EC_KEY_get0_public_key(ec_tmp_ptr);

    char *ecChar = EC_POINT_point2hex(m_gp, ec_point_pk, POINT_CONVERSION_UNCOMPRESSED, ctxptr.get());

    std::string second_key(ecChar);
    std::cout << second_key << std::endl; 
    assert (second_key == hexStr);

    OPENSSL_free(ecChar);


    // compressed or uncompressed?
    {
        std::string compressedKey ("0373D23D4E1D88903DD7DFCF0F12E842AF8AE30DB58FAE6F79A4CF8271CBE636BF");
        std::cout << "Compressed PubKey input -> " << compressedKey << std::endl; 
         // Allocate for CTX
        std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
        assert(ctxptr != nullptr);

        EC_KEY_ptr ec_key (EC_KEY_new(), &EC_KEY_free); 
        EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_set_group(ec_key.get(), ec_group);
        EC_KEY_set_asn1_flag(ec_key.get(), OPENSSL_EC_NAMED_CURVE);

        EC_POINT * m_ec = EC_POINT_new(ec_group);
        m_ec = EC_POINT_hex2point(ec_group, compressedKey.c_str(), m_ec, ctxptr.get());
        assert(m_ec != nullptr);

        if(EC_KEY_set_public_key(ec_key.get(), m_ec) <= 0){
            std::cout << "Could not assign pub key" << std::endl;
            return -1;
        }

        EVP_PKEY * pkey = EVP_PKEY_new(); 
        assert(pkey != nullptr);
        if(EVP_PKEY_assign_EC_KEY(pkey, ec_key.get()) <= 0){
            std::cout << "Failure to asign to PK" << std::endl; 
            return -1; 
        }

        //back to an ec key
        const EC_KEY * ec_tmp_ptr = EVP_PKEY_get0_EC_KEY(pkey);
        assert(ec_tmp_ptr != nullptr);

        // back to an EC-point
        const EC_POINT * ec_point_pk = EC_KEY_get0_public_key(ec_tmp_ptr);

        //char *ecChar = EC_POINT_point2hex(ec_group, ec_point_pk, POINT_CONVERSION_COMPRESSED, ctxptr.get());
        std::string compressed_pub_key = EC_POINT_point2hex(ec_group, ec_point_pk, POINT_CONVERSION_COMPRESSED, ctxptr.get());
        assert (compressed_pub_key == compressedKey); 

        std::string uncompressed_pub_key = EC_POINT_point2hex(ec_group, ec_point_pk, POINT_CONVERSION_UNCOMPRESSED, ctxptr.get());

        std::cout << "Uncompressed key -> " << uncompressed_pub_key << std::endl; 
    }

    std::cout << "Ending" << std::endl; 
    
}