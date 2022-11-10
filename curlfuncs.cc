#include <sstream>
#include <iostream>
#include "curlfuncs.h"


size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream) {
    std::string data((const char*) ptr, (size_t) size * nmemb);
    *((std::stringstream*) stream) << data;
    return size * nmemb;
}

std::string sendcurl(const std::string& curl_cmd, unsigned char*& req_data, long& datalen){
    
        CURL *curl;
        CURLcode res;
        std::stringstream out; 
        curl = curl_easy_init();
        if(curl) {
            //curl_easy_setopt(curl, CURLOPT_URL,"http://localhost:5003/ocsp");
            curl_easy_setopt(curl, CURLOPT_URL,curl_cmd.c_str());
            std::stringstream upstr; 

            curl_easy_setopt(curl, CURLOPT_POST, (long)1);
            curl_easy_setopt(curl, CURLOPT_HEADER, 0L);  //Enable Headers
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes uninitialized stack frame" bug
            curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "deflate");
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);   //Print data in STDOUT
            //END
            struct curl_slist *hs=NULL;
            hs = curl_slist_append(hs, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, datalen);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_data);

            res = curl_easy_perform(curl);
            if(res != CURLE_OK){
                std::stringstream msg ;
                msg << "CURL PANIC " << curl_easy_strerror(res) << std::endl;
                std::cout << msg.str() << std::endl; 
            }

            curl_easy_cleanup(curl);      // always cleanup 
        } 
        return out.str() ; 
}

std::string sendcurl_post(const std::string& url, const std::string& params){
      CURL *curl;
    CURLcode res;
    std::stringstream out; 
    curl = curl_easy_init();
    if(curl) {
        std::string url_params = url + "?" + params ; 

        curl_easy_setopt(curl, CURLOPT_URL,url_params.c_str());
        std::stringstream upstr; 
        curl_easy_setopt(curl, CURLOPT_POST, (long)1);
        curl_easy_setopt(curl, CURLOPT_HEADER, 0L);  //Enable Headers
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes uninitialized stack frame" bug
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "deflate");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);   //Print data in STDOUT
        //END
        struct curl_slist *hs=NULL;
        hs = curl_slist_append(hs, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");

        res = curl_easy_perform(curl);
        if(res != CURLE_OK){
            std::stringstream msg ;
            msg << "CURL PANIC POST " << curl_easy_strerror(res) << std::endl;
            std::cout << msg.str() << std::endl; 
        }

        curl_easy_cleanup(curl);      // always cleanup 
    } 
    return out.str() ; 
}
