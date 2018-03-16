#ifndef TPM2_DUPLICATE_H
#define TPM2_DUPLICATE_H

#include "tpm2_create.h"
#include "tpm2_createprimary.h"
#include "tpm2_createpolicy.h"
#include "tpm2_createak.h"

typedef struct tpm_duplicate_ctx tpm_duplicate_ctx;
struct tpm_duplicate_ctx{
    //pub
    TPM2B_PUBLIC pub;
    //dup
    TPM2B_DATA encryptionKeyIn;
    TPMT_SYM_DEF_OBJECT symmetricAlg;

    TPM2B_DATA encryptionKeyOut;
    TPM2B_PRIVATE duplicate;
    TPM2B_ENCRYPTED_SECRET outSymSeed;
} ;   
    

int do_duplicate_import(TSS2_SYS_CONTEXT *sapi_context, 
                    tpm_createprimary_ctx *src_ctx, 
                    tpm_createprimary_ctx *des_ctx,
                    tpm_create_ctx *sk_ctx,
                    createak_context *ak_ctx, 
                    create_policy_ctx *pctx) ;


int unseal(TSS2_SYS_CONTEXT *sapi_context, 
                tpm_create_ctx *sk_ctx,
                create_policy_ctx *pctx,
                TPM2B_SENSITIVE_DATA *unseal_data
            ) ;




#endif
