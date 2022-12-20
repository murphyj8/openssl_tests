#include <iostream>

#include <openssl/bn.h>
#include <certfuncs.h>
#include <conversions.h>
/*
 g++ -Wall -I. -I/usr/local/include -I/usr/certfuncs.cc curlfuncs.cc conversions.cc bnNumbers.cc -o bnNumbers -L/usr/local/lib -lssl -lcrypto -lcurl -std=c++17
*/
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

bool VerifySignature(ECDSA_SIG*& signature, const std::unique_ptr<unsigned char[]>& digest, const int& digestlen, const EC_KEY_ptr& eckey ){
    int verify_status = ECDSA_do_verify(digest.get(), digestlen, signature, eckey.get());
    if(verify_status == 1){
        std::cout << "A LITTLE SUCCESS" << std::endl; 
        return true; 
    }
    return false; 
}

int main(int argc, char * argv[]){
    std::cout << "Starting" << std::endl; 

    bn_ptr bigNumk(BN_new(), &BN_free);
    if(!BN_rand(bigNumk.get(), 256, 0,0)){
        std::cout << "Unable to generate a random number" << std::endl; 
    }



    std::cout << BN_bn2hex(bigNumk.get()) << std::endl; 

    std::string ceo_speak("The time has now come for us to ensure that we not only continue our amazing activities in R&D, but also increase our investment in this area and grow our patent output. This can only be achieved by monetizing our business and actively driving forward the company's commercial operation turning the Group into a consultancy, advisory and commercial powerhouse that cannot be ignored. We will provide best in class technological products and solutions to enterprises and governments across the globe. This is a challenge I relish. \
Since my appointment, I have set out to review the existing business and organisational structure of the Group to ensure we can build a strong and resilient nChain which, as the DNA of Blockchain, is able to take the rightful commercial lead in a fast-changing world involving Web 3, smart contracts and other smart applications including nano transactions and payment solutions. Moreover, the unique scalability of the Bitcoin (BSV) Blockchain protocol gives us the potential to considerably propel our growth over the coming months and years."); 
    
    
    std::unique_ptr<unsigned char[]> ceo_speak_bin(new unsigned char[ceo_speak.length() + 1]);
    std::fill_n(ceo_speak_bin.get(),ceo_speak.length()+1, 0x00);
    int index(0);
    for(std::string::const_iterator iter = ceo_speak.begin(); iter != ceo_speak.end(); ++ iter){
        ceo_speak_bin[index++] = *iter; 
    }

    int digestlen(0); 
    std::unique_ptr<unsigned char[]> digest = HashIt(ceo_speak_bin, index, digestlen);
    
    std::string hexDigest = binTohexStr(digest,digestlen); 

    std::cout << hexDigest << std::endl; 

    bn_ptr bigNumFromHex(BN_new(), &BN_free);
    BIGNUM * ptr = bigNumFromHex.get () ;
    if(BN_hex2bn(&ptr, hexDigest.c_str()) ==0){
        std::cout << "Unable to convert hex string to bignumber" << std::endl;
        return -1; 
    }

    bn_ptr bigNumFromBin(BN_new(), &BN_free); 
    if(BN_bin2bn(digest.get(), digestlen, bigNumFromBin.get()) == nullptr){
        std::cout << "Could not covert number from unsigned char array (hash digest)" << std::endl; 
        return -1; 
    }

    size_t hexdigest_len(0);
    bn_ptr bigNumFromHexDigest(BN_new(), &BN_free);
    std::unique_ptr<unsigned char[]> hexDigestBin =  HexStrToBin(hexDigest, &hexdigest_len);
    if(BN_bin2bn(hexDigestBin.get(),hexdigest_len, bigNumFromHexDigest.get()) == nullptr){
        std::cout << "Failed to convert hex digest string back to big number via an unsigned char array" << std::endl; 
        return -1; 
    }

    std::cout <<  BN_bn2hex(bigNumFromHex.get()) << std::endl; 
    std::cout << BN_bn2hex(bigNumFromBin.get()) << std::endl; 
    std::cout << BN_bn2hex(bigNumFromHexDigest.get()) << std::endl; 

    if(BN_cmp(bigNumFromHex.get(),bigNumFromBin.get()) != 0){
        std::cout << "Different numbers booo!!! " << std::endl; 
        return -1; 
    }

    if(BN_cmp(bigNumFromBin.get(), bigNumFromHexDigest.get()) != 0){
        std::cout << "Different numbers boo!!!" << std::endl; 
        return -1;
    }



    // use bigNumk (multiply k * G)
    


    std::string kAsStr(BN_bn2hex(bigNumk.get()));

    // groups, ec points & big numbers 
    EC_GROUP * gp = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_POINT * kG = EC_POINT_new(gp);

    // Get the order of the curve (for n) (and bit length?)
    bn_ptr n(BN_new(), ::BN_free);
    BN_CTX_ptr pCTX_get_order(BN_CTX_new(), &BN_CTX_free);
    if (!EC_GROUP_get_order(gp, n.get(), pCTX_get_order.get()))
        throw std::runtime_error("Unable to get key group order");


    // bit length 
    std::cout << BN_num_bits(n.get()) << std::endl; 

    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
    assert(ctxptr != nullptr);

    BN_CTX_ptr pCTX_mul(BN_CTX_new(), &BN_CTX_free);
    
    // invert k (mod n)
    bn_ptr kInv (BN_new(),::BN_free);
    if (!BN_mod_inverse(kInv.get(), bigNumk.get(),n.get(), ctxptr.get()))
        throw std::runtime_error("error mod inverse");

    
    if (!EC_POINT_mul(gp, kG, bigNumk.get(), nullptr, nullptr, pCTX_mul.get()))
        throw std::runtime_error("Unable to calculate public key");




    // grab the x co-ordinate

    bn_ptr x(BN_new(), &BN_free);
    bn_ptr y(BN_new(), &BN_free); 

    if (!EC_POINT_get_affine_coordinates_GFp(gp, kG, x.get(), y.get(), ctxptr.get())){
        return -1;
    }

    // create a private key (to sign with)
    EC_KEY_ptr priv_key = CreateECPrivateKey();
    const BIGNUM* my_private_key = EC_KEY_get0_private_key(priv_key.get());
    if (my_private_key == nullptr)
        throw std::runtime_error("Unable to get private key");
  

    //std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
   

    bn_ptr res_mul(BN_new(), &BN_free);
    if (!BN_mul(res_mul.get(),x.get(),my_private_key, ctxptr.get()))
        throw std::runtime_error("error");
    bn_ptr res_add (BN_new(),::BN_free);
    //if (!BN_add(res_add.get(), bigNumFromHexDigest.get(), res_mul.get()))
    if (!BN_add(res_add.get(), bigNumFromBin.get(),res_mul.get())) 
        throw std::runtime_error("error");

    bn_ptr final_sig(BN_new(), &BN_free); 
    if(!BN_mul(final_sig.get(), kInv.get(), res_add.get(), ctxptr.get()))
        throw std::runtime_error("error");

    // take the final number mod n
    bn_ptr final_sig_mod_n (BN_new(),::BN_free);
    if (!BN_mod(final_sig_mod_n.get(), final_sig.get(), n.get(), ctxptr.get()))
        throw std::runtime_error("error");

    // The signatire is r = x co-ord, s = final_sig_mod_n

    //int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

    ECDSA_SIG* new_sig = ECDSA_SIG_new(); 
    if (ECDSA_SIG_set0(new_sig, x.get(),final_sig_mod_n.get()) == 0){
        std::cout << "PANIC .. unable to set signature " << std::endl; 
        return -1; 
    }

    // verify manually generated sig
    if(!VerifySignature(new_sig, digest,digestlen, priv_key)){
        std::cout << "PANIC .. unable to verify signature" << std::endl; 
        return -1; 
    }

    const BIGNUM* bnR = ECDSA_SIG_get0_r(new_sig);
    const BIGNUM* bnS = ECDSA_SIG_get0_s(new_sig);

    std::cout 
        << "r -> " << BN_bn2hex(bnR) << "\n"
        << "s -> " << BN_bn2hex(bnS) << "\n"
        << "pub key -> " << GetPublicKeyHexString(priv_key)
        << std::endl
        ;

    std::cout << "Finishing" << std::endl; 
}