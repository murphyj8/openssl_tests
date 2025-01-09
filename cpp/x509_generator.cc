#include "x509_generator.h"

#include <iostream>
#include <string>

#include <openssl/x509.h>

#include "utils.h"
#include "tsInterface.h"

int create_root_certificate(    const std::string& URL, 
                                const std::string& groupId, 
                                const std::string& index,
                                const std::string& pubkey,
                                const std::string& country,
                                const std::string& organisation,
                                const std::string& common_name,
                                unsigned int validity,
                                const std::string& ca_cert_file,
                                int curve_nid) {
    
    
    std::cout << "Creating root certificate" << std::endl ;

    // generate a new key pair for the root certificate
    pkey_ptr temporary_key = createNewKey(curve_nid);
    

    // create a new x509
    x509_ptr cert_ptr ( template_x509( country, organisation, common_name, validity, temporary_key, groupId ) );
    std::cout << "...got templated x509" << std::endl ;

    // 1. Get the public key from the TS scheme and insert into certificate - arrived in the parameters
    pkey_ptr ts_evp_pkey = convertPubKeyStrToEVP(pubkey, curve_nid);

    if(X509_set_pubkey(cert_ptr.get(), ts_evp_pkey.get()) != 1){
        std::cout << "Error setting the public key of the certificate" << std::endl;
        return 1; 
    }
    std::cout << "...updated public key to the one from the Threshold Signature group" << std::endl ;

    // 2. Get the tbs (to-be-signed) certificate
    int tbs_len(0);
    std::unique_ptr<unsigned char[]> tbs = X509_TBS(cert_ptr, tbs_len);
    
    // 3. Hash the tbs 
    int digest(0);
    std::unique_ptr<unsigned char[]> msg = HashIt(tbs, tbs_len, digest);

    // 4. Convert the message to a string
    std::string msg_as_a_str = binTohexStr(msg, digest) ;
    std::cout << "msg_as_a_str = " << msg_as_a_str << std::endl ;

    // 5. Get the signature via TS scheme
    std::string ts_signature("");
    size_t sig_len(-1); 

    std::unique_ptr<unsigned char[]>bin_sig  =  getSignature(URL, groupId, index, msg_as_a_str, ts_signature, sig_len);
    std::cout << "ts_signature = " << ts_signature << std::endl ;

    // 6. Convert the signature to a binary
    size_t sigderlen = 0; 
    std::unique_ptr<unsigned char[]> sigderbin =  HexStrToBin(ts_signature, &sigderlen);
    
    // 7. Update the signature
    std::cout << "Signature before overwriting" << std::endl ;
    print_x509_sig(cert_ptr.get());

    const X509_ALGOR * palg;  
    const ASN1_BIT_STRING * psig;

    X509_get0_signature(&psig, &palg, cert_ptr.get());
    ASN1_BIT_STRING_set(const_cast<ASN1_BIT_STRING *> (psig), sigderbin.get(), sigderlen);

    std::cout << "Signature after overwriting" << std::endl ;
    print_x509_sig(cert_ptr.get());


    /* ------------------------------------------------------------ *
    *  save certificate to file                                     *
    * -------------------------------------------------------------*/

    file_ptr new_cert_fp(fopen(ca_cert_file.c_str(), "w"), fclose);
    if(!new_cert_fp){
        std::cout << "Error opening file " << ca_cert_file << " for output " << std::endl; 
        return 1; 
    }

    if(PEM_write_X509(new_cert_fp.get(), cert_ptr.get()) != 1){
        std::cout << "Error writing the certificate to disk" << std::endl; 
        return 1; 
    }
    return 0;

}



int create_client_certificate(  const std::string& URL, 
                                const std::string& groupId, 
                                const std::string& index,
                                unsigned int validity,
                                const std::string& ca_cert_file,
                                const std::string& csr_request_file,
                                const std::string& client_cert_file){

    std::cout << "Creating client certificate" << std::endl ;

    std::cout << "  ca_cert_file      = " << ca_cert_file << std::endl;  
    std::cout << "  csr_request_file  = " << csr_request_file << std::endl;  



    // 1.  load the CSR request
    x509_req_ptr csr_ptr(load_csr(csr_request_file));
    if(!csr_ptr){
        std::cout << "Error loading the CSR request" << std::endl; 
        return 1; 
    }

    // 2.  verify the signature on the CSR
    if (!verify_csr_signature(csr_ptr)){
        std::cout << "Error verifying the signature on the CSR" << std::endl; 
        return 1; 
    }

    // 3.  load the CA certificate
    x509_ptr ca_cert_ptr(load_ca(ca_cert_file));
    if(!ca_cert_ptr){
        std::cout << "Error loading the CA certificate" << std::endl; 
        return 1; 
    }

    // generate a new key pair for the root certificate
    // first need the curve_id from the ca_cert_file
    int curve_nid = getCurveNidFromCert(ca_cert_ptr);
    pkey_ptr temporary_key = createNewKey(curve_nid);


    // 4. Create x509 client template
    x509_ptr cert_ptr(template_client_x509( ca_cert_ptr, csr_ptr, validity, temporary_key, groupId ) );
    if(!cert_ptr){
        std::cout << "Error creating the client certificate" << std::endl; 
        return 1; 
    }

    // 5. Get the tbs (to-be-signed) certificate
    int tbs_len(0);
    std::unique_ptr<unsigned char[]> tbs = X509_TBS(cert_ptr, tbs_len);
    
    // 6. Hash the tbs 
    int digest(0);
    std::unique_ptr<unsigned char[]> msg = HashIt(tbs, tbs_len, digest);

    // 7. Convert the message to a string
    std::string msg_as_a_str = binTohexStr(msg, digest) ;
    std::cout << "msg_as_a_str = " << msg_as_a_str << std::endl ;

    // 8. Get the signature via TS scheme
    std::string ts_signature("");
    size_t sig_len(-1); 

    std::unique_ptr<unsigned char[]>bin_sig  =  getSignature(URL, groupId, index, msg_as_a_str, ts_signature, sig_len);
    std::cout << "ts_signature = " << ts_signature << std::endl ;

    // 9. Convert the signature to a binary
    size_t sigderlen = 0; 
    std::unique_ptr<unsigned char[]> sigderbin =  HexStrToBin(ts_signature, &sigderlen);
    
    // 10. Update the signature
    std::cout << "Signature before overwriting" << std::endl ;
    print_x509_sig(cert_ptr.get());

    const X509_ALGOR * palg;  
    const ASN1_BIT_STRING * psig;

    X509_get0_signature(&psig, &palg, cert_ptr.get());
    ASN1_BIT_STRING_set(const_cast<ASN1_BIT_STRING *> (psig), sigderbin.get(), sigderlen);

    std::cout << "Signature after overwriting" << std::endl ;
    print_x509_sig(cert_ptr.get());



    /* ------------------------------------------------------------ *
    *  save certificate to file                                     *
    * -------------------------------------------------------------*/

    file_ptr new_cert_fp(fopen(client_cert_file.c_str(), "w"), fclose);
    if(!new_cert_fp){
        std::cout << "Error opening file " << client_cert_file << " for output " << std::endl; 
        return 1; 
    }

    if(PEM_write_X509(new_cert_fp.get(), cert_ptr.get()) != 1){
        std::cout << "Error writing the certificate to disk" << std::endl; 
        return 1; 
    }
    
    return 0;

}