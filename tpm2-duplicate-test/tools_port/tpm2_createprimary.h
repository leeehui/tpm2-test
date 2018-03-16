#ifndef TPM2_CREATEPRIMARY_H
#define TPM2_CREATEPRIMARY_H
#include <sapi/tpm20.h>
#include "tpm2_hierarchy.h"

typedef struct tpm_createprimary_ctx tpm_createprimary_ctx;
struct tpm_createprimary_ctx {
    TPMS_AUTH_COMMAND session_data;
    tpm2_hierearchy_pdata objdata;
    TPMS_CONTEXT context;
    struct {
        UINT8 H :1;
        UINT8 g :1;
        UINT8 G :1;
    } flags;
};

int create_primary(TSS2_SYS_CONTEXT *sapi_context, 
                    char *hierarchy,
                    char *key_alg,
                    char *hash_alg,
                    tpm_createprimary_ctx *ctx) ;


#endif