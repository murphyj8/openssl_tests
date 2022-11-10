#ifndef __CURLFUNCS_H__
#define __CURLFUNCS_H__

#include <string>
#include <curl/curl.h>

size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream);
std::string sendcurl(const std::string&, unsigned char*& req_data, long& datalen); 

std::string sendcurl_post(const std::string&, const std::string&);
#endif //#ifndef __CURLFUNCS_H__