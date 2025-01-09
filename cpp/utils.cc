
#include "utils.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <cassert>
#include <cstring>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bn.h>

#include <sys/stat.h>

#define ERR_NOT_HEX  -1
#define ERR_BAD_SIZE -2
#define ERR_NO_MEM   -3



// ---------------------------------------------
// Generate a random serial number based on groupID
// ---------------------------------------------
unsigned int generate_serial_number(const std::string& groupID) {
    srand((unsigned)time(NULL));
    unsigned int random = (rand() % 101);
    unsigned int groupID_hash = std::hash<std::string>()(groupID);;
    return (random + groupID_hash);
}


// ----------- Print X509 Signature ------------
// ---------------------------------------------
void print_x509_sig(X509 *cert){

    std::cout << "Print X509 Signature: " << std::endl ;

    BIO *outbio = NULL;

    if (cert == NULL) {
        std::cout << "cert is NULL" << std::endl ;
        return;
    }


    /* ---------------------------------------------------------- *
    * Create the Output BIO's.                                    
    * ---------------------------------------------------------- */
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);


    /* ---------------------------------------------------------- *
    * Extract the certificate's signature data. 
    *    sig_type = cert->sig_alg;
    *    asn1_sig = cert->signature;
    *    sig_bytes = asn1_sig->length;
    * These structures are now opaque
    *   need to use X509_get0_tbs_sigalg and X509_ALGOR_get0
    * ---------------------------------------------------------- */

    {
        const ASN1_OBJECT *paobj;
        X509_ALGOR_get0(&paobj, NULL, NULL, X509_get0_tbs_sigalg(cert));
        int nid = OBJ_obj2nid(paobj);

        std::cout << "  - Getting the tbsCertificate signature algorithm" << std::endl ;
        std::cout <<  "\tnid long: " << OBJ_nid2ln(nid) 
                    << "\tnid short: " << OBJ_nid2sn(nid)
                    << "\tnid int: " << nid << std::endl; 
    }
 
    {
        ASN1_OBJECT *paobj;
        X509_PUBKEY_get0_param(&paobj, NULL, 0, NULL, X509_get_X509_PUBKEY(cert));
        int nid = OBJ_obj2nid(paobj);

        std::cout << "  - Getting the x509 public key" << std::endl ;
        std::cout <<  "\tnid long: " << OBJ_nid2ln(nid) 
                    << "\tnid short: " << OBJ_nid2sn(nid)
                    << "\tnid int: " << nid << std::endl; 
    }
    {
        int algo_nid;
        OBJ_find_sigid_algs(X509_get_signature_nid(cert), &algo_nid, NULL) ;  
        
        std::cout << "  - Getting signature NID" << std::endl ;
        std::cout <<  "\tnid long: " << OBJ_nid2ln(algo_nid) 
                    << "\tnid short: " << OBJ_nid2sn(algo_nid)
                    << "\tnid int: " << algo_nid << std::endl;  

        // const X509_ALGOR * palg;          

    }

    /* ---------------------------------------------------------- *
    * Print the signature type here                              *
    * ---------------------------------------------------------- */
    const X509_ALGOR * palg;  
    const ASN1_BIT_STRING * psig;

    X509_get0_signature(&psig, &palg, cert);

    BIO_printf(outbio, "Signature Print:\n");
    X509_signature_print(outbio, palg, psig) ;

    int n = psig->length;
    std::cout << "length = " << n << std::endl ;


    /* ---------------------------------------------------------- *
    * Free up all structures                                     *
    * ---------------------------------------------------------- */
    BIO_free_all(outbio);
}






// ----------------------------------------------------------
// ----------- Load a Private Key                ------------
// ----------------------------------------------------------
pkey_ptr load_private_key(const std::string& filename){

    file_ptr key_fp(fopen(filename.c_str(), "r"), fclose);
    if(!key_fp){
        std::cout << "ERROR: Unable to open file " << filename << std::endl; 
    }

    pkey_ptr the_key(PEM_read_PrivateKey(key_fp.get(), NULL, NULL, NULL), &EVP_PKEY_free);
    if(!the_key){
        std::cout << "ERROR: Unable to create the CA private key" << std::endl;  
    }

    return the_key;
}

// ----------------------------------------------------------
// ----------- Load CSR (certificate signing request)   -----
// ----------------------------------------------------------
x509_req_ptr load_csr(const std::string& filename){

    file_ptr csr_req_fp(fopen(filename.c_str(), "r"), fclose);
    if(!csr_req_fp){
        std::cout << "ERROR: Unable to open CSR request file " << filename << std::endl; 
    }

    x509_req_ptr csr_req_ptr(PEM_read_X509_REQ(csr_req_fp.get(), NULL, NULL, NULL), &X509_REQ_free);
    if(!csr_req_ptr){
        std::cout << "Unable to load the CSR req structure" << std::endl; 
    }

    return csr_req_ptr;
}

// ----------------------------------------------------------
// ----------- Load CA certificate               ------------
// ----------------------------------------------------------
x509_ptr load_ca(const std::string& ca_cert_file){

    file_ptr ca_cert_fp(fopen(ca_cert_file.c_str(), "r"), fclose);
    if(!ca_cert_fp){
        std::cout << "Unable to open file " << ca_cert_file << std::endl;
    }

    x509_ptr cacert(PEM_read_X509(ca_cert_fp.get(),NULL,NULL,NULL), &X509_free);
    if(!cacert){
        std::cout << "Unable to load the CA crt file" << std::endl; 
    }

    return cacert;
}

// ----------------------------------------------------------
// -----------Verify Signature on CSR            ------------
// ----------------------------------------------------------
int verify_csr_signature(const x509_req_ptr& csr_req_ptr){

    pkey_ptr req_pubkey(X509_REQ_get_pubkey(csr_req_ptr.get()), &EVP_PKEY_free);
    if(!req_pubkey){
        std::cout << "Error getting the public key from the certificate request" << std::endl; 
        return 0;
    }

    if (X509_REQ_verify(csr_req_ptr.get(), req_pubkey.get()) != 1){
        std::cout << "Error verifying signature on the request" << std::endl;  
        return 0;
    }
    
    std::cout << "Returning from verify_csr_signature with 0" << std::endl;
    return 1;
}



// ----------------------------------------------------------
// ----------- Generates an x509 certificate     ------------
// ----------------------------------------------------------
/* Generates a self-signed x509 certificate.
   Signed with a dummy */
x509_ptr template_x509( const std::string& country, 
                        const std::string& organisation,
                        const std::string& common_name,
                        unsigned int validity,
                        pkey_ptr& temporary_key,
                        const std::string& groupID)
{
    std::cout << "In template_x509" << std::endl ;
    std::cout << "  country:      " << country << std::endl ;
    std::cout << "  organisation: " << organisation << std::endl ;
    std::cout << "  common_name:  " << common_name << std::endl ;
    std::cout << "  validity:     " << validity << std::endl ;
    
    init_openssl();

    x509_ptr x509 (X509_new() , &X509_free);
    if(!x509){
        std::cout << "EROR: Unable to create x509 certificate" << std::endl ;
    }
    
    /* Set the serial number  */
    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), generate_serial_number(groupID));
    
    /* This certificate is valid from now until number of days (validity) in future */
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), (long)60*60*24*validity);

    
    /* We want the subject name */
    X509_NAME * name = X509_get_subject_name(x509.get());
    
    /* Set the country code, organisation and common name */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)country.c_str(),        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)organisation.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)common_name.c_str(), -1, -1, 0);
    
    /* Now set the issuer name to be same as subject name */
    X509_set_issuer_name(x509.get(), name);

    /* Set the public key for our certificate. */
    X509_set_pubkey(x509.get(), temporary_key.get());


    if(!X509_sign(x509.get(), temporary_key.get(), EVP_sha256()))
    {
        std::cerr << "Error signing certificate." << std::endl;
    }

    std::cout << "Returning templated x509 certificate" << std::endl ;

    // Before returning - lets write this certificate out to file to compare with 
    // the TS version of the certificate
    #if DEBUG
        /* ------------------------------------------------------------ *
        *  print the certificate                                       *
        * -------------------------------------------------------------*/
        const std::string cert_file( "/app/data/dropbox/TEMPLATE-ROOT-CERT.pem");

        file_ptr new_cert_fp(fopen(cert_file.c_str(), "w"), fclose);
        if(!new_cert_fp){
            std::cout << "Error opening file " << cert_file << " for output " << std::endl; 
        }

        if(PEM_write_X509(new_cert_fp.get(), x509.get()) != 1){
            std::cout << "Error writing the certificate to disk" << std::endl; 
        }
    #endif

    return x509;
}




/* Generates a client x509 certificate.
   Signed with a dummy */
x509_ptr template_client_x509( 
                        const x509_ptr& ca_cert,
                        const x509_req_ptr& csr_ptr,
                        unsigned int validity,
                        pkey_ptr& temporary_key,
                        const std::string& groupID)

{
    std::cout << "In create_client_x509" << std::endl ;

    init_openssl();


    /* -------------------------------------------------------- *
    * Build Certificate with data from request                  *
    * -------------------------------------------------------- */
   
    x509_ptr newcert_ptr(X509_new(), &X509_free);
    if(!newcert_ptr){
        std::cout << "EROR: Unable to create client x509 certificate" << std::endl ;
        return newcert_ptr;
    }

    if(X509_set_version(newcert_ptr.get(), 2) != 1){
        std::cout << "Error setting the certificate version" << std::endl;
        return newcert_ptr;
    }
    // create a new serial number
    ASN1_INTEGER_ptr new_serial_number(ASN1_INTEGER_new(), &ASN1_INTEGER_free);
    if(!new_serial_number){
        std::cout << "Error creating serial number ptr" << std::endl; 
        return newcert_ptr;
    }


    // set the serial number 
    ASN1_INTEGER_set(new_serial_number.get(), generate_serial_number(groupID));
    if(!X509_set_serialNumber(newcert_ptr.get(), new_serial_number.get())){
        std::cout << "Error setting serial number of the certificate" << std::endl; 
        return newcert_ptr;
    }


    X509_NAME * name_ptr = X509_REQ_get_subject_name(csr_ptr.get());
    if(!name_ptr){
        std::cout << "Error getting the subject from the certificate request" << std::endl;  
        return newcert_ptr;
    }

    if(X509_set_subject_name(newcert_ptr.get(), name_ptr) != 1){
        std::cout << "Error setting the certificate subject from the certificate request" << std::endl;
        return newcert_ptr;
    }


    /* -------------------------------------------------------- *
    * Extract the subject name from the CA certificate           *
    * -------------------------------------------------------- */

    X509_NAME * ca_name_ptr = X509_get_subject_name(ca_cert.get());
    if(!ca_name_ptr){
        std::cout << "Error getting subject name from CA certificate" << std::endl;  
    }

    if(X509_set_issuer_name(newcert_ptr.get(), ca_name_ptr) != 1){
        std::cout << "Error setting the issuer naame of the certificate" << std::endl; 
    }

    /* -------------------------------------------------------- *
    * Set the public key to the client's public key (from CSR)  *
    * -------------------------------------------------------- */

    pkey_ptr req_pubkey(X509_REQ_get_pubkey(csr_ptr.get()), &EVP_PKEY_free);
    if(!req_pubkey){
        std::cout << "Error getting the public key from the certificate request" << std::endl; 
    }

    if(X509_set_pubkey(newcert_ptr.get(), req_pubkey.get()) != 1){
        std::cout << "Error setting the public key of the certificate" << std::endl;
    }



    /* ---------------------------------------------------------- *
    * Set start date (now) and expiration date (+ days)*
    * -----------------------------------------------------------*/

    if(!(X509_gmtime_adj(X509_get_notBefore(newcert_ptr.get()), 0))){
        std::cout << "Error setting start time" << std::endl;  
    }

    long valid_secs = long( validity * 24 * 60 * 60) ;
    std::cout << "Validity = " << valid_secs << std::endl ;
    if(!(X509_gmtime_adj(X509_get_notAfter(newcert_ptr.get()), valid_secs))){
        std::cout << "Error setting the end time" << std::endl; 
    }

    /* ----------------------------------------------------------- *
    * Sign new certificate with a temporary key                        *
    * ------------------------------------------------------------*/


    // Sign x509 with temporary key
    if (!X509_sign(newcert_ptr.get(), temporary_key.get(), EVP_sha256())){
        std::cout << "Error signing the new certificate" << std::endl; 
    }


    // Before returning - lets write this certificate out to file to compare with 
    // the TS version of the certificate
    #if DEBUG
        /* ------------------------------------------------------------ *
        *  print the certificate                                       *
        * -------------------------------------------------------------*/
        const std::string cert_file( "/app/data/dropbox/TEMPLATE-CLIENT-CERT.pem");

        file_ptr new_cert_fp(fopen(cert_file.c_str(), "w"), fclose);
        if(!new_cert_fp){
            std::cout << "Error opening file " << cert_file << " for output " << std::endl; 
        }

        if(PEM_write_X509(new_cert_fp.get(), newcert_ptr.get()) != 1){
            std::cout << "Error writing the certificate to disk" << std::endl; 
        }
    #endif

    return newcert_ptr;
}    

// ----------------------------------------------------------
// ----------- Initialise the OPEN SSL library   ------------
// ----------------------------------------------------------
// Initialise OPENSSL
void init_openssl()
{
    std::cout << "Initialising OpenSSL" << std::endl ;
    
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}



// ----------------------------------------------------------
// ----------- Convert raw r and s to DER sig    ------------
// ----------------------------------------------------------
/* Signature from Threshold Signature is in raw "r" and "s" form 
   x509 certficiate required the DER form.  */
std::unique_ptr<unsigned char[]> 
    raw_to_DER_signature(   size_t& len, 
                            const std::string& sigr,
                            const std::string& sigs )
{

   std::cout << "sigr = " << sigr << std::endl; 
   std::cout << "sigs = " << sigs << std::endl; 


   /// Create new ECDSA_SIG
    SIG_ptr pSig(ECDSA_SIG_new(), &ECDSA_SIG_free);

    
    /// Import <r,s> into BIGNUM
    BIGNUM* raw_r = BN_new();// Will be own by pSig
    BIGNUM* raw_s = BN_new();// Will be own by pSig

    BN_hex2bn(&raw_r, sigr.c_str());
    BN_hex2bn(&raw_s, sigs.c_str());

    if (!ECDSA_SIG_set0(pSig.get(), raw_r, raw_s)){
        BN_free(raw_r);
        BN_free(raw_s);
        throw std::runtime_error("error importing <r,s> strings for ECDSA r["+ 
         sigr +"] s["+ 
         sigs +"]");
    }
    
    int sig_size = i2d_ECDSA_SIG(pSig.get(), NULL);
    std::unique_ptr<unsigned char[]> derSig (new unsigned char [sig_size]);

    unsigned char * p = derSig.get(); 
    int new_sig_size = i2d_ECDSA_SIG(pSig.get(), &p);
    assert( sig_size == new_sig_size) ;
    len = sig_size ; 
    
    return derSig; 
}

//----------------------------------------------------------
// ----------- write  key to file            ------------
// ----------------------------------------------------------
void write_key_to_file(const std::string& filename, const pkey_ptr& pkey)
{
    file_ptr key_fp(fopen(filename.c_str(), "w"), fclose);
    if(!key_fp){
        std::cout << "Error opening file " << filename << " for output " << std::endl; 
    }

    if(PEM_write_PrivateKey(key_fp.get(), pkey.get(), NULL, NULL, 0, NULL, NULL) != 1){
        std::cout << "Error writing the key to disk" << std::endl; 
    }
}


// ----------------------------------------------------------
// ----------- Create a new key                  ------------
// ----------------------------------------------------------
pkey_ptr createNewKey(int curve_id) {
    std::cout <<  "Creating a new key for the certificate" << std::endl;

    pkey_ptr pkey (EVP_PKEY_new(), &EVP_PKEY_free);

    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx (BN_CTX_new(), &BN_CTX_free );
    EC_KEY *ec_key = EC_KEY_new();
    EC_GROUP_ptr ec_group (EC_GROUP_new_by_curve_name(curve_id), &EC_GROUP_free);
    EC_KEY_set_group(ec_key, ec_group.get());

    EC_KEY_generate_key(ec_key);
    EVP_PKEY_assign_EC_KEY(pkey.get(), ec_key);
#ifdef DEBUG
        std::cout << "New key created" << std::endl;
        write_key_to_file("/app/data/dropbox/TEMPLATE-ROOT-KEY.pem", pkey);
#endif
    return pkey;

}

// ----------------------------------------------------------
// ----------- Get curve NID from cert           ------------
// ----------------------------------------------------------
int getCurveNidFromCert(const x509_ptr& cert){
    std::cout << "Getting curve NID from cert  " << std::endl;
    int curve_id = 0;
    pkey_ptr pkey (X509_get_pubkey(cert.get()), &EVP_PKEY_free);
    if (pkey == NULL) {
        std::cout << "Error getting public key from certificate" << std::endl;
        return 0;
    }

    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey.get());

    if (ec_key == NULL) {
        std::cout << "Error getting EC_KEY from public key" << std::endl;
        return 0;
    }
    // get the curve NID
    curve_id = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));

    std::cout << "Curve ID = " << curve_id << std::endl;
    return curve_id;
}

pkey_ptr  convertPubKeyStrToEVP(const std::string& the_key, int curve_id ) {
 
    pkey_ptr pkey (EVP_PKEY_new(), &EVP_PKEY_free);

    std::cout << "PubKey input -> " << the_key << std::endl; 

    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx (BN_CTX_new(), &BN_CTX_free );
    EC_KEY *ec_key = EC_KEY_new();

    // NO - don't use unique pointer as key is assigned to EVP_PKEY after creation
    // then when ec-key is freed it is still referenced by th EVP_PKEY 
    // this leads to a seg-fault

    // EC_KEY_ptr ec_key (EC_KEY_new(), &EC_KEY_free); 
    
    EC_GROUP_ptr ec_group (EC_GROUP_new_by_curve_name(curve_id), &EC_GROUP_free);
    EC_KEY_set_group(ec_key, ec_group.get());

    EC_POINT * m_ec = EC_POINT_new(ec_group.get());

    // NO - can't use unique pointer as point is updated after creation
    // EC_POINT_ptr m_ec (EC_POINT_new(ec_group.get()), &EC_POINT_free);
    m_ec = EC_POINT_hex2point(ec_group.get(), the_key.c_str(), m_ec, ctx.get());

    if(EC_KEY_set_public_key(ec_key, m_ec) <= 0){
        std::cout << "Could not assign pub key" << std::endl;
        return pkey;
    }

    if(EVP_PKEY_assign_EC_KEY(pkey.get(), ec_key) <= 0){
        std::cout << "Failure to asign to PK" << std::endl; 
        return pkey;
    }

    // free stuff
    // EC_KEY_free(ec_key); --> can't free... this will cause seg fault
    EC_POINT_free( m_ec );

    return pkey;
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

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7','8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


std::string binTohexStr(const std::unique_ptr<unsigned char[]>& data, int len)
{
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data.get()[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data.get()[i] & 0x0F];
  }
  return s;
}

std::unique_ptr<unsigned char[]> HexStrToBin(const std::string& input, size_t *l) {
  unsigned char       shift = 4, value = 0;
  unsigned char       *r, *ret;
  const unsigned char *p;
  

  r = ret = new unsigned char[input.length() / 2];
  if (ret == nullptr){
    *l = ERR_NO_MEM;
    return nullptr;
  }
  
  int lenInput = input.length(); 
  
  unsigned char * ptr = new unsigned char[lenInput]; 
  if(ptr == nullptr){
    *l = ERR_NO_MEM;
    return nullptr;
  }
  std::fill_n(ptr, lenInput, 0x00);
  
    int i (0);
    for(std::string::const_iterator iter = input.begin(); iter != input.end(); ++iter){
        ptr[i++] = *iter ; 
    }
  
  for (p = ptr;  isspace(*p);  p++);
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;


  int index = 0; 
  //while (p[0] && index < lenInput) {
  while(index < lenInput){
   ++index;
  //while (p[0]){
    switch (p[0]) {
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
        value |= (*p++ - '0') << shift;
        break;
      case 'a': case 'b': case 'c':
      case 'd': case 'e': case 'f':
        value |= (*p++ - 'a' + 0xa) << shift;
        break;
      case 'A': case 'B': case 'C':
      case 'D': case 'E': case 'F':
        value |= (*p++ - 'A' + 0xa) << shift;
        break;
      case 0:
        if (!shift) { 
          *l = ERR_NOT_HEX;
          delete [] ptr;
          delete [] ret;
          return nullptr;
        }
        break;
      default:
        if (isspace(p[0])) p++;
        else {
          *l = ERR_NOT_HEX;
          delete [] ptr;
          delete [] ret; 
          return 0;
        }
    }
    if ((shift = (shift + 4) % 8) != 0) {
      *r++ = value;
      value = 0;
    }
  }

  if (!shift) {
    *l = ERR_BAD_SIZE;
    delete [] ptr;
    delete [] ret; 
    return nullptr;
  }
  *l = (r - ret);

  std::unique_ptr<unsigned char[]> retVal ( new unsigned char[input.length()/ 2]); 
  if (retVal == nullptr){
    *l = ERR_NO_MEM; 
    delete [] ptr; 
    delete [] ret; 
  }
  for(size_t i=0; i<*l;++i){
    retVal.get()[i] = ret[i] ; 
  }
  
  delete [] ptr; 
  delete [] ret ; 
  
  return retVal;
}

