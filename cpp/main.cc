
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>


#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <cstring>
#include <vector>


#include <tsInterface.h>

#include <utils.h>
#include <x509_generator.h>


// ----------------------------------------------
// ----------- Main Entry Point      ------------
// ----------------------------------------------
int main(int argc, char* argv[]) {

    bool success(false);
    std::cout << "Running x509 generator" << std::endl; 

    std::cout << "Arguments:  " << "\n";
  
    for (int i = 0; i < argc; ++i)
        std::cout << "\t" << argv[i] << "\n";
    std::cout << std::endl ;

    // extract common arguments
    std::string URL             (argv[1]) ;
    std::string generateRoot    (argv[2]) ;
    std::string groupId         (argv[3]) ;
    std::string keyIndex        (argv[4] ) ;

    // sanity check the parameters are valid
    if (!checkParameters( URL, groupId, keyIndex)) {
        std::cout << "Parameters failed check, exiting" << std::endl ;
        return 1;
    }

    // get the public key for selected group
    std::string pubkey;
    success = getPublicKey( URL, groupId, pubkey ) ;
    if (!success) {
        std::cout << "Failed to get public key, exiting" << std::endl ;
        return 1;
    }

    // get the curve id, needed to create a key
    int curve_nid;
    success = getCurveID(URL, groupId, curve_nid);
    if (!success) {
        std::cout << "Failed to get curve id, exiting" << std::endl ;
        return 1;
    }

    
    if (success) {

        if ( generateRoot == "true") {
            std::string country         (argv[5]) ;
            std::string organisation    (argv[6]) ;
            std::string common_name     (argv[7]) ;
            unsigned int validity       (atoi( argv[8] )) ;
            std::string target_filename (argv[9]) ;

            create_root_certificate(    URL,
                                        groupId,
                                        keyIndex,
                                        pubkey,
                                        country,
                                        organisation,
                                        common_name,
                                        validity,
                                        target_filename,
                                        curve_nid);




            std::cout << "finished" << std::endl ;
            return 0 ;

        }
        else 
        {
            std::string root_filename   (argv[5]) ;
            std::string csr_filename    (argv[6]) ;
            unsigned int validity       (atoi( argv[7] )) ;
            std::string target_filename (argv[8]) ;

            create_client_certificate(  URL,
                                        groupId, 
                                        keyIndex, 
                                        validity,
                                        root_filename,  
                                        csr_filename,
                                        target_filename
                                        );
        }
    }

    return 0;
}

