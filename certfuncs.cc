#include "certfuncs.h"
#include "curlfuncs.h"
#include <iostream>
#include <sstream>


std::string asn1int(ASN1_INTEGER *bs){
    static const char hexbytes[] = "0123456789ABCDEF";
    std::stringstream ashex;
    for(int i=0; i<bs->length; ++i)
    {
        ashex << hexbytes[ (bs->data[i]&0xf0)>>4  ] ;
        ashex << hexbytes[ (bs->data[i]&0x0f)>>0  ] ;
    }
    return ashex.str();
}

std::string CertSerialNumber(const x509_ptr& x509){
    return asn1int(X509_get_serialNumber(x509.get()));
}

std::string pem(const x509_ptr& x509){
    bio_mem_ptr bio_out_ptr (BIO_new(BIO_s_mem()), &BIO_free);
    PEM_write_bio_X509(bio_out_ptr.get(), x509.get());
    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(bio_out_ptr.get(), &bio_buf);
    std::string pem = std::string(bio_buf->data, bio_buf->length);
    return pem;
}

std::string PubkeyStr(const evp_pkey_ptr& pkey_ptr){
    bio_mem_ptr bio_out_ptr (BIO_new(BIO_s_mem()), &BIO_free);
    if (!PEM_write_bio_PUBKEY(bio_out_ptr.get(), pkey_ptr.get())){
        std::cout << "Failed to write pubkey to string" << std::endl; 
        char * buf = new char[1024]; 
        unsigned long err =  ERR_get_error();
        std::cout << "ERROR CODE -> " << err << "\n" 
                    << ERR_error_string(err, buf) << std::endl; 
    
        std::cout << buf << std::endl; 
        delete [] buf; 
        return std::string(); 
    };
    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(bio_out_ptr.get(), &bio_buf);
    std::string pem = std::string(bio_buf->data, bio_buf->length);
    return pem;
}

bool IsTempX509(const x509_ptr& cert){
    X509_NAME * name_ptr = X509_get_subject_name(cert.get()); 
    int count = X509_NAME_entry_count(name_ptr);

    for(int i=0; i<count; ++i){
        X509_NAME_ENTRY *e = X509_NAME_get_entry(name_ptr, i);
        int nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(e));
        std::string field_name = OBJ_nid2sn(nid);
        if(field_name == "OU"){
            ASN1_STRING *v = X509_NAME_ENTRY_get_data(e);
            unsigned char * val_ptr_utf = nullptr; 
            int val_ptr_utf_len = ASN1_STRING_to_UTF8(&val_ptr_utf, v);
            std::string ou_val(reinterpret_cast<char *>(val_ptr_utf), val_ptr_utf_len);
            if(ou_val == ("Temporary Certificate")){
                // temp certificate return trues
                return true; 
            }
            help_openssl_free_uchar(val_ptr_utf); 
        }
    }

    return false; 
}

bool OCSP_Verify(const x509_ptr& user_cert, const x509_ptr& ca_cert){
    ocsp_ptr ocsp_req (OCSP_REQUEST_new(), &OCSP_REQUEST_free); 
    if(!ocsp_req){
        std::cout << "Unable to allocate OCSP request" << std::endl; 
        return false ; 
    }
    OCSP_CERTID * cert_ptr = OCSP_cert_to_id(EVP_sha256(), user_cert.get(), ca_cert.get());
    if(!cert_ptr){
        std::cout << "Unable to load the ocsp cert id " << std::endl; 
        return false; 
    }

    if(!OCSP_request_add0_id(ocsp_req.get(), cert_ptr)){
        std::cout << "Unable to add the id to the OCSP request " << std::endl; 
        return false; 
    }
    OCSP_request_add1_nonce(ocsp_req.get(), NULL, 8);
    unsigned char *req_data = NULL;
    long len = (long)i2d_OCSP_REQUEST(ocsp_req.get(), &req_data);

    const std::string& curl_cmd("http://localhost:5003/ocsp");
    std::string resp_buffer = sendcurl(curl_cmd, req_data, len); 
    delete req_data; 

    bio_mem_ptr mem(BIO_new(BIO_s_mem()), &BIO_free);
    BIO_write(mem.get(), resp_buffer.c_str(),resp_buffer.length() + 1);


    OCSP_RESPONSE * resp = nullptr; 
    resp = d2i_OCSP_RESPONSE_bio(mem.get(), NULL);
    if(!resp){
        std::cout << "Unable to decode OCSP response" << std::endl; 
        return false; 
    }

    int status = OCSP_response_status(resp);
    if(status != OCSP_RESPONSE_STATUS_SUCCESSFUL){
        std::cout << "Unsuccessful OCSP response" << std::endl; 
        return false; 
    }

    OCSP_BASICRESP * basic = OCSP_response_get1_basic(resp);
    if(!basic){
        std::cout << "Unable to extract the basic response info" << std::endl; 
        return false; 
    }

    if(OCSP_resp_count(basic) == 0){
        std::cout << "OCSP_resp_count returned zero" << std::endl; 
        return false;
    }

    for (int i = 0; i < OCSP_resp_count(basic); ++i){
        OCSP_SINGLERESP * single_response = OCSP_resp_get0(basic, i);
        if(single_response == nullptr){
            std::cout << "Error looking up the basic response" << std::endl;
        }

        if(OCSP_single_get0_status(single_response, nullptr, nullptr, nullptr, nullptr) 
            != V_OCSP_CERTSTATUS_GOOD){
            std::cout << "Error Validiating certificate with OCSP responder " << std::endl ;
            return false; 
        }else{
            //std::cout << CertSerialNumber(usercert) << " is valid.." << std::endl; 
            std::cout << "Verified " << std::endl; 
        }
    }
    return true; 
}

bool LoadPriKeyFromFile(const std::string& prikeypath, evp_pkey_ptr& pkey_ptr){
    file_ptr prikey_fp(fopen(prikeypath.c_str(), "r"), fclose);
    if (!prikey_fp){
        std::cout << "Unable to open key file " << prikeypath << std::endl; 
        return false; 
    }
    pkey_ptr.reset(PEM_read_PrivateKey(prikey_fp.get(), NULL, NULL, NULL)); 
    if(RSA_check_key(EVP_PKEY_get1_RSA(pkey_ptr.get()))) {
        std::cout << "Valid Identity key" << std::endl;
    }else{
        std::cout << "invalid identity key" << std::endl; 
        return false;
    }
    return true; 
}

bool WritePriKeyToFile(const std::string& file_name, const evp_pkey_ptr& prikey){
    file_ptr prikey_fp(fopen(file_name.c_str(), "wb"), fclose);
    if (!prikey_fp){
        std::cout << "Unable to open key file " << file_name << std::endl; 
        return false; 
    }
    if (!PEM_write_PrivateKey(prikey_fp.get(),prikey.get(),NULL,NULL,0,0,NULL)){
        std::cout << "Unable to write the private key to file " << std::endl; 
        return false; 
    }
    return true; 
}

bool WritePubKeyToFile(const std::string& file_name, const evp_pkey_ptr& prikey){
    file_ptr pubkey_fp(fopen(file_name.c_str(), "wb"), fclose);
    if (!pubkey_fp){
        std::cout << "Unable to open key file " << file_name << std::endl; 
        return false; 
    }
    if (!PEM_write_PUBKEY(pubkey_fp.get(),prikey.get())){
        std::cout << "Unable to write the public key to file " << std::endl; 
        return false; 
    }
    return true; 
}
bool LoadPubKeyfromFile(const std::string&, evp_pkey_ptr&){
    
    return true; 
}

evp_pkey_ptr CreateRSAkey (){
    // NB. The RSA * is deleted as part of the EVP_PKEY_assign_RSA func call below
    evp_pkey_ptr rsa_ptr (EVP_PKEY_new(), &EVP_PKEY_free); 
    RSA * rsa_tmp_ptr = RSA_new(); 

    bn_ptr bn_ptr (BN_new(), &BN_free); 
    BN_set_word(bn_ptr.get(), RSA_F4);

    if (!RSA_generate_key_ex(rsa_tmp_ptr, 4096,bn_ptr.get(), NULL)){
        std::cout << "Failed to generate key " << std::endl; 
    }

    EVP_PKEY_assign_RSA(rsa_ptr.get(), rsa_tmp_ptr);

    return rsa_ptr;
}

EC_KEY_ptr CreateECPrivateKey(){
    EC_KEY_ptr ec_priv_key (EC_KEY_new(), &EC_KEY_free); 
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(nid);
    EC_KEY_set_group(ec_priv_key.get(), ec_group);
    EC_KEY_set_asn1_flag(ec_priv_key.get(), OPENSSL_EC_NAMED_CURVE);
    if(!EC_KEY_generate_key(ec_priv_key.get()))
        throw std::runtime_error("Unable to generate EC Key");

    if(!EC_KEY_check_key(ec_priv_key.get())){
        throw std::runtime_error("Failed to passed ec key checks");
    }
    return ec_priv_key; 
}

EC_KEY_ptr CreateECPrivateKeyFromSharedSecert(const std::string& shared_secret){
    BIGNUM * sec_ptr = BN_new(); 
    if(!BN_hex2bn(&sec_ptr, shared_secret.c_str())){
        BN_free(sec_ptr);
        throw std::runtime_error("Could not create a big number for the secret key"); 
    }

    EC_KEY_ptr shared_ec_ptr(EC_KEY_new(), &EC_KEY_free);
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(nid);
    EC_KEY_set_group(shared_ec_ptr.get(), ec_group);
    EC_KEY_set_asn1_flag(shared_ec_ptr.get(), OPENSSL_EC_NAMED_CURVE);

    EC_POINT_ptr pub_key(EC_POINT_new(ec_group), &EC_POINT_free);
    BN_CTX_ptr ctx(BN_CTX_new(), &BN_CTX_free);

    if (!EC_POINT_mul(ec_group, pub_key.get(), sec_ptr, NULL, NULL, ctx.get())){
        BN_free(sec_ptr); 
        throw std::runtime_error("Failed to create shared public key");
    }       

    if(!EC_KEY_set_private_key(shared_ec_ptr.get(),sec_ptr)){
        BN_free(sec_ptr);
        throw std::runtime_error("Unable to assign private ec key");
    }

    if(!EC_KEY_set_public_key(shared_ec_ptr.get(), pub_key.get())){
        BN_free(sec_ptr);
        throw std::runtime_error("Unable to set the public key on the shared key");
    }
    if(!EC_KEY_check_key(shared_ec_ptr.get())){
        BN_free(sec_ptr);
        throw std::runtime_error("Invalid key .. for creating a sharred key");
    }

    BN_free(sec_ptr); 
    return shared_ec_ptr; 
}

std::string GetPublicKeyHexString(const EC_KEY_ptr& ec_key_ptr)
{
    BN_CTX_ptr nb_ctx(BN_CTX_new(), &BN_CTX_free);
    const EC_GROUP* pEC_GROUP = EC_KEY_get0_group(ec_key_ptr.get());
    const EC_POINT* pEC_POINT = EC_KEY_get0_public_key(ec_key_ptr.get());

    STR_ptr pStr(EC_POINT_point2hex(pEC_GROUP, pEC_POINT, POINT_CONVERSION_UNCOMPRESSED, nb_ctx.get()), &help_openssl_free_char);
    const std::string pubkey_hex(pStr.get());
    return pubkey_hex;
}

bool WriteECPrivateKey(const std::string& file_name, const EC_KEY_ptr& ec_key_p){
    file_ptr prikey_fp(fopen(file_name.c_str(), "wb"), fclose);
    if (!prikey_fp){
        std::cout << "Unable to open key file " << file_name << std::endl; 
        return false; 
    }
    if(!PEM_write_ECPrivateKey(prikey_fp.get(), ec_key_p.get(), NULL, NULL, 0, 0,NULL)){
        std::cout << "Unable to write the file " << file_name << std::endl; 
        return false; 
    }
    return true; 
}
bool LoadECPrivateKeyFromFile(const std::string& file_name, EC_KEY_ptr& ec_key_p){
    file_ptr prikey_fp(fopen(file_name.c_str(), "rb"), fclose); 
    if(!prikey_fp){
        std::cout << "Unable to open key file " << file_name << std::endl; 
        return false; 
    }

    EC_KEY * ptr_tmp = PEM_read_ECPrivateKey(prikey_fp.get(), NULL, NULL, NULL);
    if(!ptr_tmp){
        std::cout << "Unable to reaad the key file " << file_name << std::endl; 
        return false;
    }

    // set the bastard group
    EC_GROUP * gp = EC_GROUP_new_by_curve_name(NID_secp384r1);
    if (gp == nullptr){
        std::cout << "Ubale to get EC key group " << std::endl; 
        return false; 
    }
    EC_KEY_set_group(ec_key_p.get(), gp);
    ec_key_p.reset(ptr_tmp); 

    const BIGNUM* pBN = EC_KEY_get0_private_key(ec_key_p.get());
    if (pBN == nullptr){
        std::cout << "Uable to read newly loaded EC Private key " << std::endl; 
        return false; 
    }

    //const EC_GROUP* pEC_GROUP = EC_KEY_get0_group(ec_key_p.get());
    //if (pEC_GROUP == nullptr){
    //    std::cout << "Ubale to get EC key group " << std::endl; 
    //    return false; 
    //}

    EC_POINT_ptr pEC_POINT(EC_POINT_new(gp), &EC_POINT_free);
    BN_CTX_ptr pCTX_mul(BN_CTX_new(), &BN_CTX_free);
    if (!EC_POINT_mul(gp, pEC_POINT.get(), pBN, nullptr, nullptr, pCTX_mul.get())){
        std::cout << "Unable to calculate public key " << std::endl; 
        return false; 
    }
    
    if (!EC_KEY_set_public_key(ec_key_p.get(), pEC_POINT.get())){
        std::cout << "Unable to set the public key" << std::endl; 
        return false; 
    }

    
    EC_KEY_set_asn1_flag(ec_key_p.get(), OPENSSL_EC_NAMED_CURVE); 

    if(!EC_KEY_check_key(ec_key_p.get())){
        std::cout << "Invalid EC KEY loaded from file" << std::endl; 
        return false; 
    }
    return true; 
}

bool LoadX509FromFile(const std::string file_name, x509_ptr& cert_ptr){
     // load up x509 & try to get the public_key
    file_ptr js_cert_fp(fopen(file_name.c_str(), "r"), fclose);
    if(!js_cert_fp){
        std::cout << "Unable to open file " << file_name << std::endl;
        return 1;
    }

    cert_ptr.reset(PEM_read_X509(js_cert_fp.get(),NULL,NULL,NULL));
    if(!cert_ptr){
        std::cout << "Unable to load the CA crt file" << std::endl;
        return 1;
    }
    return true; 
}

bool LoadX09CSRFromFile(const std::string& file_name, x509_req_ptr& cert_req_ptr){
    file_ptr cert_req_fp(fopen(file_name.c_str(), "r"), fclose);
    if(!cert_req_fp){
        std::cout << "Unable to load the csr " << file_name << std::endl; 
        return false; 
    }

    cert_req_ptr.reset(PEM_read_X509_REQ(cert_req_fp.get(), NULL, NULL, NULL));
    if(!cert_req_ptr){
        std::cout << "Unable to read the cert request" << std::endl; 
        return false;
    }
    return true; 
}

std::string PubKeyPemFromCert(const x509_ptr& cert_ptr){
    evp_pkey_ptr pubkey_ptr (X509_get_pubkey(cert_ptr.get()), &EVP_PKEY_free); 
    if(!pubkey_ptr){
        std::cout << "Unable to extract public key from crt file " << std::endl; 
        return std::string(); 
    }
    return PubkeyStr(pubkey_ptr) ; 
}
std::string CreateSecret(const std::string& pemPubkey, const EC_KEY_ptr& id_key){
    bio_mem_ptr mem(BIO_new(BIO_s_mem()), &BIO_free);
    //bio_mem_ptr bio(BIO_new(BIO_s_mem()), &BIO_free_all);
    const int bio_write_ret = BIO_write(mem.get(), static_cast<const char*>(pemPubkey.c_str()), (int)pemPubkey.size());
    if (bio_write_ret <= 0)
        throw std::runtime_error("Error reading PEM public key");

    /// Import the public key
    EC_KEY* pub_key_ec = nullptr;
    if (!PEM_read_bio_EC_PUBKEY(mem.get(), &pub_key_ec, NULL, NULL))
        throw std::runtime_error("Error reading public key when verifying signature");
    EC_KEY_ptr pEC_KEY_pub(pub_key_ec, &EC_KEY_free);// wrap to unique_ptr for safety
    EC_KEY_set_asn1_flag(pEC_KEY_pub.get(), OPENSSL_EC_NAMED_CURVE);

    /// Get group generator point
    const EC_GROUP* pEC_GROUP = EC_KEY_get0_group(pEC_KEY_pub.get());
    if (pEC_GROUP == nullptr)
        throw std::runtime_error("Unable to import EC key group");
    /// Get group generator point
    const EC_GROUP* mEC_GROUP = EC_KEY_get0_group(id_key.get());
    if (mEC_GROUP == nullptr)
        throw std::runtime_error("Unable to get EC key group");

    {/// Check EC Group are compatible
        BN_CTX_ptr pCTX(BN_CTX_new(), &BN_CTX_free);
        if (0 != EC_GROUP_cmp(pEC_GROUP, mEC_GROUP, pCTX.get()))
            throw std::runtime_error("Error calculating shared secret, incompatible elliptic curve group");;
    }

    const EC_POINT* pEC_GENERATOR = EC_GROUP_get0_generator(pEC_GROUP);
    if (pEC_GENERATOR == nullptr)
        throw std::runtime_error("Unable to get key group generator");

    /// Get public key
    const EC_POINT* their_pub_key = EC_KEY_get0_public_key(pEC_KEY_pub.get());
    if (their_pub_key == nullptr)
        throw std::runtime_error("Unable to import public EC key");

    /// Get private key
    const BIGNUM* my_private_key = EC_KEY_get0_private_key(id_key.get());
    if (my_private_key == nullptr)
        throw std::runtime_error("Unable to get private key");

    EC_POINT_ptr shared_secret_point(EC_POINT_new(pEC_GROUP), &EC_POINT_free);
    BN_CTX_ptr pCTX_mul(BN_CTX_new(), &BN_CTX_free);
    if (!EC_POINT_mul(pEC_GROUP, shared_secret_point.get(), nullptr, their_pub_key, my_private_key, pCTX_mul.get()))
        throw std::runtime_error("Unable to calculate shared secret");

    bn_ptr shared_secret_x(BN_new(),&BN_free);
    BN_CTX_ptr pCTX_get(BN_CTX_new(), &BN_CTX_free);
    if(!EC_POINT_get_affine_coordinates_GFp(pEC_GROUP, shared_secret_point.get(), shared_secret_x.get(), nullptr, pCTX_get.get()))
        throw std::runtime_error("Unable to get x coordinate of shared secret");

    STR_ptr pStr(BN_bn2hex(shared_secret_x.get()), &help_openssl_free_char);
    const std::string shared_secret_x_str(pStr.get());
    return shared_secret_x_str;
}

std::unique_ptr<unsigned char []> X509_TBS(const x509_ptr& cert, int& output_len ){

    unsigned char * my_val = nullptr; 
    output_len = i2d_re_X509_tbs(cert.get(), &my_val);  

    if(output_len < 0){
        throw std::runtime_error("Some weird shit going down"); 
    }

    std::unique_ptr<unsigned char[]> tbs (new unsigned char[output_len]);
    for(int i=0; i<output_len; i++){
        tbs[i] = my_val[i];
    }
    return tbs; 
}

x509_req_ptr generate_cert_req(const std::string& req_path, const std::string& priv_key_path) {
    x509_req_ptr req(X509_REQ_new(), &X509_REQ_free);
    if(req == nullptr){
        throw std::runtime_error("Unable to create an X509_REQ");
    }

    std::cout << "Loading key from pem file" << std::endl; 
    EC_KEY_ptr prikey_ptr(EC_KEY_new(), &EC_KEY_free);
    if(!LoadECPrivateKeyFromFile(priv_key_path, prikey_ptr)){
        throw std::runtime_error("Unable to load private key to generate CSR " + req_path);
    }
    std::cout << "Key loaded" << std::endl; 
    //evp_pkey_ptr pkey(EVP_PKEY_new(), &EVP_PKEY_free);
    std::string hexStr = GetPublicKeyHexString(prikey_ptr); 
    std::cout << hexStr<< std::endl; 

    //const EC_POINT * ec_ptr = EC_KEY_get0_public_key(prikey_ptr.get());

    EVP_PKEY* pkey = EVP_PKEY_new(); 
    assert(pkey != nullptr);
    //if(EVP_PKEY_assign_EC_KEY(pkey.get(), prikey_ptr.get()) <= 0){
    if(EVP_PKEY_assign_EC_KEY(pkey, prikey_ptr.get()) <= 0){
        std::cout << "Failure to asign to PK" << std::endl; 
        throw std::runtime_error("Unable to convert EC_KEY to EVP_PKEY structure");
    }
    std::cout << "private key assigned " << std::endl; 
    //if (X509_REQ_set_pubkey(req.get(), pkey.get()) == 0) {
    if (X509_REQ_set_pubkey(req.get(), pkey) == 0) {
        std::cout << "Unable to set public key in CSR" << std::endl; 
        throw std::runtime_error("Unable to set public key in CSR");
    }

    // add the subject (set these up from a toml file)
    std::cout << "Public key set " << std::endl; 
    const std::string& commonName("nChain");
    const std::string& countryName("uk");
    const std::string& state("Greater London");
    const std::string& locality("London");
    const std::string& email_addr("j.murphy@nchain.com");
    const std::string& org("ResearchAndDevelopment");

    x509_name_ptr subject = CreateSubject(commonName, countryName, state, locality, email_addr, org); 
	X509_REQ_set_subject_name(req.get(), subject.get());

    //if (X509_REQ_sign(req.get(), pkey.get(), EVP_sha256()) == 0) {
    if (X509_REQ_sign(req.get(), pkey, EVP_sha256()) == 0) {
        std::cout << "Failed to sign certificate" << std::endl; 
        throw std::runtime_error("Failed to sign certificate");
    }
    return req;
}

bool WriteCSR(const x509_req_ptr& cert_req, const std::string& path) {
    file_ptr x509req_fp(fopen(path.c_str(), "wb"), fclose);
    if (!x509req_fp){
        std::cout << "Unable to open x509 req file " << path << std::endl; 
        return false; 
    }

    if(PEM_write_X509_REQ(x509req_fp.get(), cert_req.get()) ==0){
        std::cout << "Unable to write the output CSR " << path << std::endl; 
        return false;
    };
    return true;
}

bool WriteX509Cert(const x509_ptr& cert, const std::string& cert_path){
    file_ptr x509_fp(fopen(cert_path.c_str(), "wb"), fclose);
    if(!x509_fp){
        return false; 
    }
    if(PEM_write_X509(x509_fp.get(), cert.get()) == 0){
        std::cout << "Unable to write the x509 to " << cert_path << std::endl;
        return false; 
    }
    return true;
}

x509_ptr CreateFromCSR(const x509_req_ptr& req, const std::string& prikey_path){

    EC_KEY_ptr prikey_ptr(EC_KEY_new(), &EC_KEY_free);
    if(!LoadECPrivateKeyFromFile(prikey_path, prikey_ptr)){
        throw std::runtime_error("Unable to load private key to generate CSR " + prikey_path);
    }

    std::string hexStr = GetPublicKeyHexString(prikey_ptr); 
    std::cout << "Public key from loaded key " << hexStr << std::endl; 

    x509_ptr cert(X509_new(), &X509_free);

    // set the version (X509_VERSION_3 -> 2)
    if (X509_set_version(cert.get(), 2) != 1){
        throw std::runtime_error("Failed to set the x509 version in CreateFromCSR");
    }

    // set the serial number
    bn_ptr bn(BN_new(), &BN_free);
    if(!BN_rand(bn.get(), 256, 0, 0)){
        throw std::runtime_error("Unable to generate a random number for the certificate serial number");
    }
    ASN1_INTEGER * ptr = BN_to_ASN1_INTEGER(bn.get(), nullptr); 

    if (!X509_set_serialNumber(cert.get(), ptr)) {
        throw std::runtime_error("Error setting serial number of the certificate");
    }

    // set the subject from the request
    //x509_name_ptr subj (X509_REQ_get_subject_name(req.get()), &X509_NAME_free); 
    X509_NAME * subj = X509_REQ_get_subject_name(req.get()); 
    if(subj == nullptr){
        throw std::runtime_error("Unable to extract the subject from the request");
    }

    if (X509_set_subject_name(cert.get(), subj) != 1){
        throw std::runtime_error("Error setting subject name of certificate");
    }

    //extract the public key csr_request
    EVP_PKEY * pkey_raw_ptr = X509_REQ_get_pubkey(req.get());
    if(pkey_raw_ptr == nullptr){
        throw std::runtime_error("Failed to extract pubkey into a raw pointer");
    }

    //evp_pkey_ptr req_pubkey(X509_REQ_get_pubkey(req.get()), &EVP_PKEY_free);
    //if(req_pubkey == nullptr){
    //    throw std::runtime_error("Failed to extract public key from request");
    //}
    
    //std::cout << "Reading public key from certificate -> " << PubkeyStr(req_pubkey) << std::endl; 
    EC_KEY_ptr ec_tmp_ptr( EVP_PKEY_get0_EC_KEY(pkey_raw_ptr), &EC_KEY_free);
    std::cout << "Before Assert" << std::endl; 
    assert(ec_tmp_ptr != nullptr);
    std::cout << "After Assert" << std::endl; 
    const EC_POINT * ec_point_pk = EC_KEY_get0_public_key(ec_tmp_ptr.get());
    assert(ec_point_pk != nullptr);
    std::cout << "After EC_KEY_get0_public_key " << std::endl; 
    EC_GROUP * gp = EC_GROUP_new_by_curve_name(NID_secp384r1);
    // Allocate for CTX
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    assert(ctxptr != nullptr);

    std::cout << "Before converting EC_Point to HEX" << std::endl; 
    char *ecChar = EC_POINT_point2hex(gp, ec_point_pk, POINT_CONVERSION_UNCOMPRESSED, ctxptr.get());
    std::cout << "PUB KEY FROM EVP_PKEY AS AN ECPOINT " << ecChar << std::endl; 

    //std::cout << "PUB KEY CONVERTED FROM AN EVP_PKEY -> " << GetPublicKeyHexString(ec_tmp_ptr) << std::endl; 
    // Optionally: Use the public key to verify the signature 
#if 0
    if (X509_REQ_verify(req.get(), pkey_raw_ptr) != 1){
        throw std::runtime_error("Failed to verify the signature in the CSR");
    }
#endif
    // set the new certificate public key
    if (X509_set_pubkey(cert.get(), pkey_raw_ptr) != 1){
        throw std::runtime_error("Failed to set the public key in the new certificate");
    }

    //Set X509V3 start date (now) and expiration date (+365 days)
    if (!X509_gmtime_adj(X509_get_notBefore(cert.get()),0)){
        throw std::runtime_error("Failed to set the start time on the certificate");
    }
    long valid_secs = 31536000;
    if(!X509_gmtime_adj(X509_get_notAfter(cert.get()), valid_secs)){
        throw std::runtime_error("Failed to set the end time on the certificate");
    }

    // extensions can be set here?
    
    // load up the private key & sign it. 
#if 0 
    EC_KEY_ptr prikey_ptr(EC_KEY_new(), &EC_KEY_free);
    if(!LoadECPrivateKeyFromFile(prikey_path, prikey_ptr)){
        throw std::runtime_error("Unable to load private key to generate CSR " + prikey_path);
    }

    std::string hexStr = GetPublicKeyHexString(prikey_ptr); 
    std::cout << "Public key from loaded key " << hexStr << std::endl; 
#endif 
    EVP_PKEY* pkey = EVP_PKEY_new(); 

    assert(pkey != nullptr);

    //if(EVP_PKEY_assign_EC_KEY(pkey.get(), prikey_ptr.get()) <= 0){
    if(EVP_PKEY_assign_EC_KEY(pkey, prikey_ptr.get()) <= 0){
        std::cout << "Failure to asign to PK" << std::endl; 
        throw std::runtime_error("Unable to convert EC_KEY to EVP_PKEY structure");
    }

    if (!X509_sign(cert.get(), pkey,  EVP_sha256())) {
        throw std::runtime_error("Unable top sign X509");
    }

    //EVP_PKEY_free(pkey); 
    return cert; 
}

x509_name_ptr CreateSubject(const std::string& commonName, const std::string& countryName, const std::string& stateOrProv, 
                            const std::string& locality, const std::string& emailAddress, const std::string& org){

    x509_name_ptr subject(X509_NAME_new(), &X509_NAME_free);

    std::unique_ptr<unsigned char []> cn (new unsigned char [commonName.length() + 1]);
    std::fill_n(cn.get(), commonName.length()+1, 0x00);
    int i=0;
    for(std::string::const_iterator iter = commonName.begin(); iter != commonName.end(); ++ iter){
        cn[i++] = *iter; 
    }
    if( X509_NAME_add_entry_by_txt(subject.get(), "commonName", MBSTRING_ASC, cn.get(), -1, -1, 0) == 0){
        std::cout << "Failed to add commonName to X509 subject" << std::endl; 
        throw std::runtime_error("ailed to add commonName to X509 subject");
    }

    std::unique_ptr<unsigned char[]> country(new unsigned char[countryName.length()+1]); 
    std::fill_n(country.get(),countryName.length()+1, 0x00);
    i=0; 
    for(std::string::const_iterator iter = countryName.begin(); iter != countryName.end(); ++ iter){
        country[i++] = *iter; 
    }
    if(X509_NAME_add_entry_by_txt(subject.get(), "countryName", MBSTRING_ASC, country.get(), -1, -1, 0) == 0){
        throw std::runtime_error("ailed to add countryName to X509 subject");
    }

    std::unique_ptr<unsigned char[]> prov (new unsigned char[stateOrProv.length()+1]) ; 
    std::fill_n(prov.get(), stateOrProv.length()+1, 0x00);
    i=0;
    for(std::string::const_iterator iter = stateOrProv.begin();iter != stateOrProv.end(); ++ iter){
        prov[i++] = *iter ; 
    }
    if(X509_NAME_add_entry_by_txt(subject.get(), "stateOrProvinceName", MBSTRING_ASC, prov.get(), -1, -1, 0) == 0){
        throw std::runtime_error("ailed to add stateOrProvinceName to X509 subject");
    }

    std::unique_ptr<unsigned char[]> loc_name (new unsigned char[locality.length()+1]) ; 
    std::fill_n(loc_name.get(), locality.length()+1, 0x00);
    i=0;
    for(std::string::const_iterator iter = locality.begin();iter != locality.end(); ++ iter){
        loc_name[i++] = *iter ; 
    }
    if(X509_NAME_add_entry_by_txt(subject.get(), "localityName", MBSTRING_ASC, loc_name.get(), -1, -1, 0) == 0){
        throw std::runtime_error("ailed to add localityName to X509 subject");
    }

    std::unique_ptr<unsigned char[]> email_ptr (new unsigned char[emailAddress.length()+1]) ; 
    std::fill_n(email_ptr.get(), emailAddress.length()+1, 0x00);
    i=0;
    for(std::string::const_iterator iter = emailAddress.begin();iter != emailAddress.end(); ++ iter){
        email_ptr[i++] = *iter ; 
    }
    if(X509_NAME_add_entry_by_txt(subject.get(), "emailAddress", MBSTRING_ASC, email_ptr.get(), -1, -1, 0) == 0){
        throw std::runtime_error("ailed to add emailAddress to X509 subject");
    }

    std::unique_ptr<unsigned char[]> org_ptr (new unsigned char[org.length()+1]) ; 
    std::fill_n(org_ptr.get(), org.length()+1, 0x00);
    i=0;
    for(std::string::const_iterator iter = org.begin();iter != org.end(); ++ iter){
        org_ptr[i++] = *iter ; 
    }
    if(X509_NAME_add_entry_by_txt(subject.get(), "organizationName", MBSTRING_ASC, org_ptr.get(), -1, -1, 0) == 0){
        throw std::runtime_error("ailed to add organizationName to X509 subject");
    }
    return subject;

}

