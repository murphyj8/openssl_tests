#ifndef __TSINTERFACE_H__
#define __TSINTERFACE_H__

#include <string>
#include <memory>

bool checkParameters(   const std::string& URL,
                        const std::string& groupID, 
                        const std::string& keyIndex );

bool checkGroupID(  const std::string& URL, 
                    const std::string& groupID );

bool checkEphemeralKey( const std::string& URL, 
                        const std::string& groupId, 
                        const std::string& keyIndex );

bool getPublicKey(  const std::string& URL, 
                    const std::string& groupID, 
                    std::string& pubKey );

bool getCurveID(    const std::string& URL,
                    const std::string& groupID, 
                    int& curve_id );

std::unique_ptr<unsigned char[]> getSignature(  
                    const std::string& URL, 
                    const std::string& groupID, 
                    const std::string& keyIndex, 
                    const std::string& message,
                    std::string& sig_DER,
                    size_t& sig_len );

int getState(   const std::string& URL, 
                const std::string& groupID );

#endif //#ifndef __TSINTERFACE_H__