//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;
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
#include "tpm2_createpolicy.h"

//see Figure27 on page 232 of "TPM library specification - part 1"
void rc_parse(TSS2_RC rc){
    UINT8 rc_ser[12];
    LOG_INFO("RC=0x%0x", rc);
    if( (rc & 0xfffff000) != 0x0 )
    {
        LOG_INFO("RC in higher level");
        return;
    }
    for(int i=0; i<12; i++)
    {
        rc_ser[i] = (UINT8)((rc>>i) & 0x1);
    }
    if( (rc_ser[8] | rc_ser[7]) == 0x0 )
    {
        LOG_INFO("TPM 1.2 RC");
        return;
    }
    if( rc_ser[7] ==  0x0)//bit 7
    {
        LOG_INFO("Format 0 rc");
        if( rc_ser[10] )
        {
            LOG_INFO("Vendor defined");
            return;
        }
        if( rc_ser[11] )
        {
            LOG_INFO("Warning code: 0x%x", rc & 0x7f);
            return;
        }
        LOG_INFO("Error code: 0x%x", rc & 0x7f);
        return;
    }
    LOG_INFO("Format 1 rc");
    if( rc_ser[6] )
    {
        LOG_INFO("Parameter(0x%x) error: 0x%x", (rc>>8)&0xf, rc&0x3f );
        return;
    }
    if( rc_ser[11] ) {
        LOG_INFO("Session(0x%x) error: 0x%x", (rc >> 8) & 0x7, rc & 0x3f);
        return;
    }
    LOG_INFO("Handle(0x%x) error: 0x%x", (rc >> 8) & 0x7, rc & 0x3f);
    return;
}


static bool parse_policy_type_specific_command(TSS2_SYS_CONTEXT *sapi_context, createak_context *ak_ctx, create_policy_ctx *pctx) {


    tpm2_session_data *session_data =
            tpm2_session_data_new(pctx->common_policy_options.policy_session_type);
    if (!session_data) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session_set_authhash(session_data,
            pctx->common_policy_options.policy_digest_hash_alg);

    pctx->common_policy_options.policy_session = tpm2_session_new(sapi_context,
            session_data);

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(pctx->common_policy_options.policy_session);
/*
    TSS2_RC rval = Tss2_Sys_PolicyLocality(sapi_context,
                                            handle,
                                            0,
                                            pctx->locality_policy_options.locality,
                                            0);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyLocality, rval);
        return false;
    }
*/

    TSS2_RC rval = Tss2_Sys_PolicyCommandCode(sapi_context,
                                        handle,
                                        0,
                                        TPM2_CC_Duplicate,
                                        0);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyCommandCode, rval);
        return false;
    }

    bool result = tpm2_policy_get_digest(sapi_context, pctx->common_policy_options.policy_session,
                                    &pctx->common_policy_options.policy_digest);
    if (!result) {
        LOG_ERR("Could not tpm2_policy_get_digest");
        return false;
    }
    pctx->common_policy_options.policy_digest_list.count++;

/*
   result = tpm2_session_restart(sapi_context, 
                                pctx->common_policy_options.policy_session);
    if (!result) {
        LOG_ERR("Could not restart policy session");
        return false;
    }

    rval = Tss2_Sys_PolicyLocality(sapi_context,
                                            handle,
                                            0,
                                            pctx->locality_policy_options.locality,
                                            0);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyLocality, rval);
        return false;
    }

    rval = Tss2_Sys_PolicyCommandCode(sapi_context,
                                        handle,
                                        0,
                                        TPM2_CC_Unseal,
                                        0);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyCommandCode, rval);
        return false;
    }

    result = tpm2_policy_get_digest(sapi_context, pctx->common_policy_options.policy_session,
                                    &pctx->common_policy_options.policy_digest_list.digests[1]);
    if (!result) {
        LOG_ERR("Could not tpm2_policy_get_digest");
        return false;
    }

    pctx->common_policy_options.policy_digest_list.count++;


	rval = Tss2_Sys_PolicyOR(sapi_context,
					handle,
					0,
					&pctx->common_policy_options.policy_digest_list,
					0);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyOR, rval);
        return false;
    }

    result = tpm2_policy_get_digest(sapi_context, pctx->common_policy_options.policy_session,
                                    &pctx->common_policy_options.policy_digest);
    if (!result) {
        LOG_ERR("Could not tpm2_policy_get_digest");
        return false;
    }
*/

    rval = TSS2_RETRY_EXP(Tss2_Sys_ContextLoad(sapi_context, &ak_ctx->ak.context, &ak_ctx->ak.out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextLoad, rval);
        return false;
    }
    #define TPM2B_SIZE(type) (sizeof (type) - 2)
    #define TPM2B_NAMED_INIT(type, field) \
    { \
        .size = TPM2B_SIZE (type), \
        .field = { 0 } \
    }
	TPMT_TK_VERIFIED ticket =  { 
        TPM2_ST_VERIFIED, 
        TPM2_RH_ENDORSEMENT, 
        TPM2B_NAMED_INIT(TPM2B_DIGEST,buffer),
    };
    
    //TPMT_TK_VERIFIED ticket;
    TPM2B_NONCE nonce = {
                    .size   = TPM2_SHA256_DIGEST_SIZE,
                    .buffer = {0 }
    };
    #define TPM2B_SIZE(type) (sizeof (type) - 2)
    #define TPM2B_NAMED_INIT(type, field) \
    { \
        .size = TPM2B_SIZE (type), \
        .field = { 0 } \
    }
    TPM2B_DIGEST policy_ref = TPM2B_NAMED_INIT(TPM2B_DIGEST,buffer);

    //LOG_ERR("ticket size: 0x%x", ticket.digest.size);
    rval = Tss2_Sys_PolicyAuthorize(sapi_context,
								handle,
								0,
								&pctx->common_policy_options.policy_digest,
								&policy_ref,
								&ak_ctx->ak.out.name,
								&ticket,
								0
								);

    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyAuthorize, rval);
        return false;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, ak_ctx->ak.out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }


    result = tpm2_policy_get_digest(sapi_context, pctx->common_policy_options.policy_session,
                                    &pctx->common_policy_options.policy_digest);
    if (!result) {
        LOG_ERR("Could not tpm2_policy_get_digest");
        return false;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }

    tpm2_session_free(&pctx->common_policy_options.policy_session);

    return true;
}


static bool get_hash_data(TSS2_SYS_CONTEXT *sapi_context, create_policy_ctx *pctx, TPM2B_DIGEST *result) {
   
    TPM2B_AUTH nullAuth = TPM2B_EMPTY_INIT;
    TPMI_DH_OBJECT sequenceHandle;
    TPMT_TK_HASHCHECK validation;
    TSS2L_SYS_AUTH_COMMAND cmdAuthArray = { 1, {{.sessionHandle = TPM2_RS_PW, 
            .nonce = TPM2B_EMPTY_INIT, .hmac = TPM2B_EMPTY_INIT,
            .sessionAttributes = 0, }}};

    #define TPM2B_SIZE(type) (sizeof (type) - 2)
    #define TPM2B_NAMED_INIT(type, field) \
    { \
        .size = TPM2B_SIZE (type), \
        .field = { 0 } \
    }
	TPM2B_DIGEST policy_ref = TPM2B_NAMED_INIT(TPM2B_DIGEST,buffer);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_HashSequenceStart(sapi_context, NULL, &nullAuth,
        pctx->common_policy_options.policy_digest_hash_alg, &sequenceHandle, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_HashSequenceStart, rval);
        return rval;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sapi_context, sequenceHandle,
            &cmdAuthArray, (TPM2B_MAX_BUFFER *)&pctx->common_policy_options.policy_digest, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_SequenceUpdate, rval);
        return false;
    }
/*
    rval = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sapi_context, sequenceHandle,
            &cmdAuthArray, (TPM2B_MAX_BUFFER *)nonce.buffer, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_SequenceUpdate, rval);
        return false;
    }
*/
    rval = TSS2_RETRY_EXP(Tss2_Sys_SequenceComplete(sapi_context, sequenceHandle,
            &cmdAuthArray, (TPM2B_MAX_BUFFER *)&policy_ref, TPM2_RH_PLATFORM, result, &validation,
            NULL));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_SequenceComplete, rval);
        return false;
    }


}


static bool sign_and_verify(TSS2_SYS_CONTEXT *sapi_context,
                            createak_context *ak_ctx, 
                            create_policy_ctx *pctx) {

    TPMT_SIG_SCHEME in_scheme;
    TPMT_SIGNATURE signature;
    TPMT_TK_HASHCHECK validation;
    TSS2L_SYS_AUTH_COMMAND sessions_data = {1, {
        {
        .sessionHandle = TPM2_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = 0,
    }}};
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    #define TPM2B_SIZE(type) (sizeof (type) - 2)
    #define TPM2B_NAMED_INIT(type, field) \
    { \
        .size = TPM2B_SIZE (type), \
        .field = { 0 } \
    }
	TPM2B_DIGEST hash_result = TPM2B_NAMED_INIT(TPM2B_DIGEST,buffer);

    bool result = get_signature_scheme(sapi_context, ak_ctx->ak.out.handle, ak_ctx->ak.in.alg.digest, &in_scheme);
    if (!result) {
        return false;
    }
    validation.tag = TPM2_ST_HASHCHECK;
    validation.hierarchy = TPM2_RH_ENDORSEMENT;
    memset(&validation.digest, 0, sizeof(validation.digest));

    get_hash_data(sapi_context, pctx, &hash_result);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Sign(sapi_context, ak_ctx->ak.out.handle,
            &sessions_data, &hash_result, &in_scheme, &validation, &signature,
            &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Sign, rval);
        return false;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_VerifySignature(sapi_context, ak_ctx->ak.out.handle, NULL,
           &hash_result, &signature, &pctx->common_policy_options.ticket, &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_VerifySignature, rval);
        return false;
    }

    return true;
}


static bool __start_policy(TSS2_SYS_CONTEXT *sapi_context,
                            TPM2_CC command_to_bind,
                            createak_context *ak_ctx, 
                            create_policy_ctx *pctx
                            ) {

    tpm2_session_data *session_data =
            tpm2_session_data_new(pctx->common_policy_options.policy_session_type);
    if (!session_data) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session_set_authhash(session_data,
            pctx->common_policy_options.policy_digest_hash_alg);

    pctx->common_policy_options.policy_session = tpm2_session_new(sapi_context, session_data);

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(pctx->common_policy_options.policy_session);
    
    if (command_to_bind == TPM2_CC_Unseal) {

        TSS2_RC rval = Tss2_Sys_PolicyLocality(sapi_context,
                                                handle,
                                                0,
                                                pctx->locality_policy_options.locality,
                                                0);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_PolicyLocality, rval);
            return false;
        }
    }
    
    TSS2_RC rval = Tss2_Sys_PolicyCommandCode(sapi_context,
                                        handle,
                                        0,
                                        command_to_bind,
                                        0);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyCommandCode, rval);
        return false;
    }

/*
	rval = Tss2_Sys_PolicyOR(sapi_context,
					handle,
					0,
					&pctx->common_policy_options.policy_digest_list,
					0);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyOR, rval);
        return false;
    }
*/
    bool result = tpm2_policy_get_digest(sapi_context, pctx->common_policy_options.policy_session,
                                    &pctx->common_policy_options.policy_digest);
    if (!result) {
        LOG_ERR("Could not tpm2_policy_get_digest");
        return false;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_ContextLoad(sapi_context, &ak_ctx->ak.context, &ak_ctx->ak.out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextLoad, rval);
        return false;
    }

    sign_and_verify(sapi_context, ak_ctx, pctx);
    
    //TPMT_TK_VERIFIED ticket;
    TPM2B_NONCE nonce = {
                    .size   = TPM2_SHA256_DIGEST_SIZE,
                    .buffer = {0 }
    };

    #define TPM2B_SIZE(type) (sizeof (type) - 2)
    #define TPM2B_NAMED_INIT(type, field) \
    { \
        .size = TPM2B_SIZE (type), \
        .field = { 0 } \
    }
	TPM2B_DIGEST policy_ref = TPM2B_NAMED_INIT(TPM2B_DIGEST,buffer);
    //LOG_ERR("ticket size: 0x%x", ticket.digest.size);
    rval = Tss2_Sys_PolicyAuthorize(sapi_context,
								handle,
								0,
								&pctx->common_policy_options.policy_digest,
								(TPM2B_NONCE *)&policy_ref,
								&ak_ctx->ak.out.name,
								&pctx->common_policy_options.ticket,
								0
								);

    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicyAuthorize, rval);
        return false;
    }
    result = tpm2_policy_get_digest(sapi_context, pctx->common_policy_options.policy_session,
                                    &pctx->common_policy_options.policy_digest);
    if (!result) {
        LOG_ERR("Could not tpm2_policy_get_digest");
        return false;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, ak_ctx->ak.out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }
   
    return true;
}



int create_policy(TSS2_SYS_CONTEXT *sapi_context, createak_context *ak_ctx, create_policy_ctx *pctx) {

    bool result = parse_policy_type_specific_command(sapi_context, ak_ctx, pctx);
    if (!result) {
        return 1;
    }

    return 0; 
}

int start_policy(TSS2_SYS_CONTEXT *sapi_context,
                            TPM2_CC command_to_bind,
                            createak_context *ak_ctx, 
                            create_policy_ctx *pctx
                            ) {
    bool result = __start_policy(sapi_context,
                            command_to_bind,
                            ak_ctx, 
                            pctx
                            ) ;
    if (!result) {
        return 1;
    }  
    return 0; 
}
