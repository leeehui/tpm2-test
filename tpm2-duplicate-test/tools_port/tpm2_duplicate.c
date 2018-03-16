#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "pcr.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

#include "lib/log.h"
#include "tpm2_duplicate.h"

    //duplicate
tpm_duplicate_ctx dup_ctx = {
        .encryptionKeyIn = {0},
        .symmetricAlg = { .algorithm = TPM2_ALG_NULL },
        .encryptionKeyOut = { 0 },
        .duplicate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer),
        .outSymSeed = TPM2B_TYPE_INIT(TPM2B_ENCRYPTED_SECRET, secret)
};



int do_duplicate_import(TSS2_SYS_CONTEXT *sapi_context, 
                    tpm_createprimary_ctx *src_ctx, 
                    tpm_createprimary_ctx *des_ctx,
                    tpm_create_ctx *sk_ctx,
                    createak_context *ak_ctx, 
                    create_policy_ctx *pctx) {

    TSS2L_SYS_AUTH_COMMAND sessionsData;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    //TPM2B_PUBLIC         outPublic = TPM2B_EMPTY_INIT;
    //TPM2B_PRIVATE        outPrivate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    sk_ctx->session_data.sessionHandle = tpm2_session_get_handle(pctx->common_policy_options.policy_session);
    sessionsData.count = 1;
    sessionsData.auths[0] = sk_ctx->session_data;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_ContextLoad(sapi_context, &src_ctx->context, &src_ctx->objdata.out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextLoad, rval);
        return -5;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_ContextLoad(sapi_context, &des_ctx->context, &des_ctx->objdata.out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextLoad, rval);
        return -5;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_ContextLoad(sapi_context, &sk_ctx->context, &sk_ctx->out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextLoad, rval);
        return -5;
    }

    rval  = Tss2_Sys_Duplicate(sapi_context,
                            sk_ctx->out.handle,
                            des_ctx->objdata.out.handle,
                            &sessionsData,
                            &dup_ctx.encryptionKeyIn,
                            &dup_ctx.symmetricAlg,
                            &dup_ctx.encryptionKeyOut,
                            &dup_ctx.duplicate,
                            &dup_ctx.outSymSeed,
                            &sessionsDataOut
    );
    if (rval != TPM2_RC_SUCCESS) {  
        LOG_PERR(Tss2_Sys_Duplicate, rval);
        return 1;
    }


    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, sk_ctx->out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return -5;
    }
    
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, src_ctx->objdata.out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return -5;
    }

    sessionsData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = Tss2_Sys_Import(sapi_context,
                         des_ctx->objdata.out.handle,
                         &sessionsData,
                         &dup_ctx.encryptionKeyOut,
                         &sk_ctx->out.pub,
                         &dup_ctx.duplicate,
                         &dup_ctx.outSymSeed,
                         &dup_ctx.symmetricAlg,
                         &sk_ctx->out.priv,
                         &sessionsDataOut
    );
    if (rval != TPM2_RC_SUCCESS) {  
        LOG_PERR(Tss2_Sys_Import, rval);
        return 1;
    }

    rval = Tss2_Sys_Load(sapi_context,
                       des_ctx->objdata.out.handle,
                       &sessionsData,
                       &sk_ctx->out.priv,
                       &sk_ctx->out.pub,
                       &sk_ctx->out.handle,
                       &sk_ctx->out.name,
                       &sessionsDataOut
    );
    if (rval != TPM2_RC_SUCCESS) {  
        LOG_PERR(Tss2_Sys_Load, rval);
        return 1;
    }
/*
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, sk_ctx->session_data.sessionHandle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }
*/  
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, des_ctx->objdata.out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return -5;
    }
    tpm2_session_free(&pctx->common_policy_options.policy_session);
    return 0; 
}

int unseal(TSS2_SYS_CONTEXT *sapi_context, 
                tpm_create_ctx *sk_ctx,
                create_policy_ctx *pctx,
                TPM2B_SENSITIVE_DATA *unseal_data
            ) {

    TSS2L_SYS_AUTH_COMMAND sessionsData;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    sk_ctx->session_data.sessionHandle = tpm2_session_get_handle(pctx->common_policy_options.policy_session);
    sessionsData.count = 1;
    sessionsData.auths[0] = sk_ctx->session_data;


    TSS2_RC rval = Tss2_Sys_Unseal(sapi_context,
                         sk_ctx->out.handle,
                         &sessionsData,
                         unseal_data,
                         &sessionsDataOut
    );
    if (rval != TPM2_RC_SUCCESS) {  
        LOG_PERR(Tss2_Sys_Unseal, rval);
        return 1;
    }

}
