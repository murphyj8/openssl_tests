#ifndef X509_GENERATOR_H_    
#define X509_GENERATOR_H_

#include <string>

int create_root_certificate(    const std::string& URL, 
                                const std::string& groupId, 
                                const std::string& index,
                                const std::string& pubkey,
                                const std::string& country,
                                const std::string& organisation,
                                const std::string& common_name,
                                unsigned int validity,
                                const std::string& ca_cert_file,
                                int curve_nid);

int create_client_certificate(  const std::string& URL, 
                                const std::string& groupId, 
                                const std::string& index,
                                unsigned int validity,
                                const std::string& ca_cert_file,
                                const std::string& csr_request_file,
                                const std::string& client_cert_file);

#endif /* X509_GENERATOR_H_ */

