#include "tsInterface.h"

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

#include <iostream>
#include <vector>

#include <thread>
#include <chrono>


#include "utils.h"

using json = nlohmann::json;


/*-------------------------------------------------------------
    Checks parameters (groupID and key index) are valie
    Returns true if found, false on failure
--------------------------------------------------------------*/
bool checkParameters(   const std::string& URL,
                        const std::string& groupID, 
                        const std::string& keyIndex) {

    // check the groupID is valid
    if (!checkGroupID( URL, groupID )) {
        std::cerr << "ERROR: groupID " << groupID << " not found. Exiting" << std::endl ;
        return false;
    }
    std::cout << "Group ID exists, continuing" << std::endl ;

    // check key is valid
    if (!checkEphemeralKey( URL, groupID, keyIndex)) {
        std::cerr   << "ERROR: groupID " << groupID 
                    << "does not have a key at index " << keyIndex 
                    << ".  Exiting" << std::endl ;
        return false;
    }
    std::cout << "Ephemeral key exists, continuing" << std::endl ;

    return true ;
}


/*-------------------------------------------------------------
    Calls the rest interface to get a list of group IDs
    Ensures the parameter groupID exists in the list
    Returns true if found, false on failure
--------------------------------------------------------------*/
bool checkGroupID( const std::string& URL, const std::string& groupID )
{
    std::cout << "Checking Group ID" << std::endl ;
    auto res = cpr::Get(cpr::Url{ URL + "/groups_ids" });

    if (res.status_code != 200) {
        std::cerr   << "ERROR: " << URL <<  "/groups_ids returned status code: " 
                    << res.status_code << std::endl ; 
        return false ;
    }

    auto j = json::parse(res.text) ;
    bool found(false) ;
    try
        {
            std::vector<std::string> groupList = j["group_list"];
            for (auto it = groupList.begin(); it != groupList.end(); it++) {
                if (*it == groupID) 
                    found = true ; 
            }
        }
        catch (nlohmann::detail::type_error& e)
        {
            std::cout << "out of range: " << e.what() << '\n';
        }

    return found;
}


/*-------------------------------------------------------------
    Check theres an ephemeral key available
    at the given index for the given groupID
    Returns true on success, false on failure
--------------------------------------------------------------*/
bool checkEphemeralKey( const std::string& URL,
                        const std::string& groupID, 
                        const std::string& keyIndex)
{

    std::cout << "Getting ephemeral key(s)" << std::endl ;

    auto res = cpr::Get(  cpr::Url{ URL + "/list_keys" },
                        cpr::Parameters{{"gid", groupID}} );
    
    if (res.status_code != 200) {
        std::cerr   << "ERROR: " << URL <<  "/list_keys returned status code: " 
                    << res.status_code << std::endl ; 
        return false ;
    }

    auto j = json::parse(res.text) ;
    bool valid(false) ;
    try
        {
            nlohmann::json keys = j["keys"];   

            if ( stoul(keyIndex) < keys.size()) 
                valid = true ;
        }
        catch (nlohmann::detail::type_error& e)
        {
            std::cout << "out of range: " << e.what() << '\n';
        }

    return valid;
}


/*-------------------------------------------------------------
    Get the public key for a given group
    Returns true on success, false on failure
      - public key available via reference parameter
--------------------------------------------------------------*/
bool getPublicKey(  const std::string& URL,
                    const std::string& groupID, 
                    std::string& pubKey )
{
    std::cout << "Getting public key" << std::endl ;

    std::string pubkey_url = URL + "/get_public_key";
    auto res = cpr::Get(cpr::Url{ pubkey_url },
        cpr::Parameters{{"gid", groupID}});
    if (res.status_code == 200)
    {
        auto j = json::parse(res.text);
        try
        {
            pubKey = j["public key"];
        }
        catch (nlohmann::detail::type_error& e)
        {
            std::cout << "out of range: " << e.what() << '\n';
        }
        std::cout << "public key = " << pubKey << std::endl ;
    }
    else
    {
        std::cout << "ERROR: Unexpected status_code: " << res.status_code 
            << ", url = " << pubkey_url 
            << ", gid = " << groupID 
            << std::endl ;
        return false;
    }

    return true ;
}

/*------------------------------------------------------------- 
    Get the curve ID (NID) for a given group
    Reutrns true on success, false on failure
        - cuve_id availalbe via reference parameter 
--------------------------------------------------------------*/
bool getCurveID(    const std::string& URL,
                    const std::string& groupID, 
                    int& curve_id )
{
    std::cout << "Getting curve ID" << std::endl ;

    std::string curve_url = URL + "/group_info";
    auto res = cpr::Get(cpr::Url{ curve_url },
        cpr::Parameters{{"gid", groupID}});
    if (res.status_code == 200)
    {
        auto j = json::parse(res.text);
        try
        {
            curve_id = j["curve_id"];
        }
        catch (nlohmann::detail::type_error& e)
        {
            std::cout << "out of range: " << e.what() << '\n';
        }
        std::cout << "curve_id = " << curve_id << std::endl ;
    }
    else
    {
        std::cout << "ERROR: Unexpected status_code: " << res.status_code 
            << ", url = " << curve_url 
            << ", gid = " << groupID 
            << std::endl ;
        return false;
    }

    return true ;
}



/*-------------------------------------------------------------
    Gets a TS signature
    
--------------------------------------------------------------*/
std::unique_ptr<unsigned char[]>  getSignature(  
                    const std::string& URL,
                    const std::string& groupID, 
                    const std::string& keyIndex, 
                    const std::string& message,
                    std::string& sig_DER,
                    size_t& sig_len
                     ) 
{
    std::cout << "Calling Sign" << std::endl ;
    std::string the_url = URL + "/sign";
    std::string hashme = "false";
    auto res = cpr::Get(cpr::Url{ the_url },
        cpr::Parameters{{"gid", groupID}, 
                        {"index", keyIndex}, 
                        {"message", message}, 
                        {"hashme", hashme}});

    if (res.status_code != 200)
    {
        std::cout << "ERROR: Unexpected status_code: " << res.status_code 
            << ", url = " << the_url 
            << ", gid = " << groupID 
            << std::endl ;
        return nullptr;
    }

    // Get the signature (and public key is returned)
    std::cout << "Now getting the signature " << std::endl ;


    
    // Wait until in signature state

    int state (0) ;
        int counter (0);
        while ( (state != 5) && (counter < 10) ) 
        {
            state = getState(URL, groupID) ;
            
            std::this_thread::sleep_for(std::chrono::milliseconds(2000)); 
            ++counter ;

        }


    the_url = URL + "/get_signature_pk";

    res = cpr::Get(cpr::Url{ the_url },
        cpr::Parameters{{"gid", groupID}, });
    if (res.status_code == 200)
    {
        auto j = json::parse(res.text);
        std::cout << "json: " << j << std::endl ;
        try
        {
           
            std::string pub_key = j["public key"];
            std::cout << "Got public key: " << pub_key << std::endl; 

            // we expect there to be two values in a list, r and s
            std::vector<std::string> signature = j["signature"]; 
            if ( signature.size() != 2 ) {
                std::cerr << "ERROR: unexpected signature size !" << std::endl ;
            }

            std::string sigr = signature[0] ;
            std::string sigs = signature[1] ;

            std::cout << "Converting raw r and s to DER signature" << std::endl ;
            // size_t sig_len(-1); 
            std::unique_ptr<unsigned char[]>  sigDERTest = 
                raw_to_DER_signature( sig_len, sigr,sigs ) ;

            
            sig_DER = binTohexStr(sigDERTest, sig_len);
            std::cout << "sigDERTest = " << sig_DER << std::endl ;
            std::cout << "len = " << sig_len << std::endl ;

            return sigDERTest; 


        }
        catch (nlohmann::detail::type_error& e)
        {
            std::cout << "out of range: " << e.what() << '\n';
        }
        
    }
    else
    {
        std::cout << "ERROR: Unexpected status_code: " << res.status_code 
            << ", url = " << the_url 
            << ", gid = " << groupID 
            << std::endl ;
        return nullptr;
    }
    return nullptr;   
}


int getState(   const std::string& URL,
                const std::string& groupID ) 
{
    std::string the_url = URL + "/state";
    auto res = cpr::Get(cpr::Url{ the_url },
        cpr::Parameters{{"gid", groupID}});

    if (res.status_code == 200)
    {
        auto j = json::parse(res.text);
        try
        {
            int state = j["state"];
            return state ;
        }
        catch (nlohmann::detail::type_error& e)
        {
            std::cout << "out of range: " << e.what() << '\n';
            return 0 ;
        }
    }
    else
    {
        std::cout << "ERROR: Unexpected status_code: " << res.status_code 
            << ", url = " << the_url 
            << ", gid = " << groupID 
            << std::endl ;
        
    }
    return 0;
}