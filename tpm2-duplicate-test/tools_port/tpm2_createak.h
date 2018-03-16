#ifndef TPM2_CREATEAK_H
#define TPM2_CREATEAK_H
#include <sapi/tpm20.h>

typedef struct createak_context createak_context;
struct createak_context {
    struct {
        TPM2_HANDLE handle;
        TPMS_CONTEXT context;
        TPM2B_AUTH auth;
    } ek;
    struct {
        struct {
            TPM2B_AUTH auth;
            struct {
                TPM2_ALG_ID type;
                TPM2_ALG_ID digest;
                TPM2_ALG_ID sign;
            } alg;
        } in;
        struct {
            TPM2B_NAME name;
            TPM2B_PUBLIC pub;	
            TPM2B_PRIVATE priv; 
            TPM2_HANDLE handle;       
        } out;
        TPMS_CONTEXT context;
    } ak;
    struct {
        TPM2B_AUTH auth;
    } owner;
};


int create_ak(TSS2_SYS_CONTEXT *sapi_context,  createak_context *ctx) ;


#endif

