#include <iostream>

#include "conversions.h"
#include "certfuncs.h"

std::unique_ptr<unsigned char []> HashIt(const std::unique_ptr<unsigned char[]>& msg, const int& len, int& digestlen){
    SHA256_CTX ctx;
    std::unique_ptr<unsigned char []> digest (new unsigned char[SHA256_DIGEST_LENGTH]);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, msg.get(), len);
    SHA256_Final(digest.get(), &ctx);
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    digestlen = SHA256_DIGEST_LENGTH;
    return digest;
}

bool CreateECDSAKey(const std::string& key_file_name){
    EC_KEY_ptr ec_pri_key = CreateECPrivateKey(); 
    if (!WriteECPrivateKey(key_file_name, ec_pri_key)){
        std::cout << "UNABLE TO WRITE EC PRIV KEY" << std::endl; 
        return false; 
    }

    return true;
}

// takes a message digest & a signing key
 ECDSA_SIG * CreateSignature(const std::unique_ptr<unsigned char[]>& digest, const EC_KEY_ptr& eckey, const int& digestlen){
    EC_GROUP * gp = EC_GROUP_new_by_curve_name(nid); 
    assert(gp != nullptr);

    ECDSA_SIG *signature = ECDSA_do_sign(digest.get(), digestlen, eckey.get());

    assert(signature != nullptr); 

    const BIGNUM* bnR = ECDSA_SIG_get0_r(signature);
    const BIGNUM* bnS = ECDSA_SIG_get0_s(signature);

    STR_ptr rStr(BN_bn2hex(bnR), &help_openssl_free_char);
    STR_ptr sStr(BN_bn2hex(bnS), &help_openssl_free_char);
    const std::string r_hex_str(rStr.get());
    const std::string s_hex_str(sStr.get());
    std::cout << "r -> " << r_hex_str << "\n" << "s -> " << s_hex_str << std::endl; 
    return signature; 

}

bool VerifySignature(const ECDSA_SIG*& signature, const std::unique_ptr<unsigned char[]>& digest, const int& digestlen, const EC_KEY_ptr& eckey ){
    int verify_status = ECDSA_do_verify(digest.get(), digestlen, signature, eckey.get());
    if(verify_status == 1){
        std::cout << "A LITTLE SUCCESS" << std::endl; 
        return true; 
    }
    return false; 
}

int main(int argc, char * argv[]){
    std::cout << "Starting" << std::endl; 
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    const std::string& key_1("./ec-secp384r1-priv-key.pem");
    const std::string& key_2("./ec-secp384r1-priv-key-two.pem");

    const std::string& csr_1("./csr_1.csr");
    //const std::string& csr_openssl("./test.csr");
    const std::string& csr_openssl("./example.com.csr");
    const std::string& cert_1("./cert_1.crt");

    //if(!CreateECDSAKey(key_1)){
    //    std::cout << "Failed to create key_1" << std::endl; 
    //    return -1;
    //}

    //std::cout << PubkeyStr(k)
    //if(!CreateECDSAKey(key_2)){
    //    std::cout << "Failed to create key_2" << std::endl; 
    //    return -1; 
    //}

    // create a CSR using key1_1
    //x509_req_ptr csr = generate_cert_req(csr_1,key_1);


    x509_req_ptr csr (X509_REQ_new(), &X509_REQ_free);
    if(!LoadX09CSRFromFile(csr_openssl, csr)){
        std::cout << "Unable to load the csr .. panic" << std::endl;
        return -1; 
    }

    // can I verify it here. 
    EVP_PKEY * pkey_raw_ptr = X509_REQ_get_pubkey(csr.get());
    if(pkey_raw_ptr == nullptr){
        throw std::runtime_error("Failed to extract pubkey into a raw pointer");
    }
#if 0 
    if (X509_REQ_verify(csr.get(), pkey_raw_ptr) != 1){
        ERR_get_state();
        char * buf = new char[1024]; 
        unsigned long err =  ERR_get_error();
        std::cout << "ERROR CODE -> " << err << "\n" 
                    << ERR_error_string(err, buf) << std::endl; 
    
        std::cout << buf << std::endl; 
        delete [] buf; 
        throw std::runtime_error("Failed to verify the signature in the CSR in the main program");
    }

    if(!WriteCSR(csr,csr_1)){
        std::cout << "Failed to write CSR to file " << csr_1 << std::endl; 
        return -1;
    }
#endif
    // create an x509 from the CSR, sign with key_2 

    // extract the tbs structure, sign with a different private key & push the signature back in
    // will it verify
    x509_ptr cert_ptr = CreateFromCSR(csr,key_2);


    // get the tbs strcutre 
    int tbs_len(0);
    std::unique_ptr<unsigned char[]> tbs = X509_TBS(cert_ptr, tbs_len);
    std::cout << "Length of tbs -> " << tbs_len << std::endl; 
    for (int i=0; i<tbs_len; ++ i){
          printf("%02x", tbs.get()[i]);
    }

    int digest(0);
    //hash it 
    std::unique_ptr<unsigned char[]> msg = HashIt(tbs, tbs_len, digest);
    // sign it? 
    std::cout << "\ndigest length -> " << digest << std::endl; 
    for (int i=0; i<digest; ++ i){
          printf("%02x", msg.get()[i]);
    }

    std::cout << std::endl; 
    EC_KEY_ptr prikey_ptr(EC_KEY_new(), &EC_KEY_free);
    if(!LoadECPrivateKeyFromFile(key_2, prikey_ptr)){
        throw std::runtime_error("Unable to load private key to manually sign  " + key_2);
    }
    // load the key
    const ECDSA_SIG * sig = CreateSignature(msg, prikey_ptr, digest); 

    if(!VerifySignature(sig, msg, digest, prikey_ptr)){
        std::cout << "Unable to manually create a signature" << std::endl; 
        return -1; 
    }

    // DER Format it

    int sig_size = i2d_ECDSA_SIG(sig, NULL);
    std::cout << "Size of sig in DER -> " << sig_size << std::endl; 
    std::unique_ptr<unsigned char[]> der_sig (new unsigned char[sig_size]);
    std::fill_n(der_sig.get(), sig_size, 0x00);
    unsigned char * der_sig_raw = der_sig.get(); 
    int new_sig_size = i2d_ECDSA_SIG(sig, &der_sig_raw);
    
    // convert to hex & print
    std::cout << binTohexStr(der_sig, sig_size)  << std::endl; 
    /* ---------------------------------------------------------- *
    * Print the signature type here                              *
    * ---------------------------------------------------------- */
    const X509_ALGOR * palg;  
    const ASN1_BIT_STRING * psig;


    X509_get0_signature(&psig, &palg, cert_ptr.get());
    BIO               *outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_printf(outbio, "Signature Print:\n");

    X509_signature_print(outbio, palg, psig) ;

    int n = psig->length;
    std::cout << "length = " << n << std::endl ;
    X509_get0_signature(&psig, &palg, cert_ptr.get());
    
    //ASN1_BIT_STRING * hackyPsig = (ASN1_BIT_STRING * ) ((void *) psig);
    //ASN1_BIT_STRING_set(hackyPsig, der_sig.get(), sig_size);
    //copy_psig = const_cast<ASN1_BIT_STRING *> (psig); 
    ASN1_BIT_STRING_set(const_cast<ASN1_BIT_STRING *> (psig), der_sig.get(), sig_size);


    if(!WriteX509Cert(cert_ptr, cert_1)){
        std::cout << "Failed to write the x509 to the file -> " << cert_1 << std::endl; 
        return -1;
    }

    // can I fit the binary data 'signing' to the TSEXample
    // introduce TS group
    std::cout << std::endl; 
    std::cout << "Ending" << std::endl; 

}