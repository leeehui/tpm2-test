#ifndef TPM2_CREATEEK_H
#define TPM2_CREATEEK_H
#include <sapi/tpm20.h>
#include "tpm2_hierarchy.h"

typedef struct createek_context createek_context;
struct createek_context {
    struct {
        TPMS_AUTH_COMMAND owner;
        TPMS_AUTH_COMMAND endorse;
        TPMS_AUTH_COMMAND ek;
    } passwords;
    tpm2_hierearchy_pdata objdata;
    TPMS_CONTEXT context;
};

int create_ek(TSS2_SYS_CONTEXT *sapi_context, char *alg_type, createek_context *ctx) ;


#endif

