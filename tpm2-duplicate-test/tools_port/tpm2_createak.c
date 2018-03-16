//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <sapi/tpm20.h>

#include "tpm2_convert.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "files.h"
#include "tpm2_util.h"
#include "tpm2_session.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"

#include "lib/log.h"
#include "tpm2_createak.h"


/*
 * TODO: All these set_xxx_signing_algorithm() routines could likely somehow be refactored into one.
 */
static bool set_rsa_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg, TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM2_ALG_NULL) {
        sign_alg = TPM2_ALG_RSASSA;
    }

    in_public->publicArea.parameters.rsaDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM2_ALG_RSASSA :
    case TPM2_ALG_RSAPSS :
        in_public->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR("The RSA signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_ecc_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg,
        TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM2_ALG_NULL) {
        sign_alg = TPM2_ALG_ECDSA;
    }

    in_public->publicArea.parameters.eccDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM2_ALG_ECDSA :
    case TPM2_ALG_SM2 :
    case TPM2_ALG_ECSCHNORR :
    case TPM2_ALG_ECDAA :
        in_public->publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR("The ECC signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_keyed_hash_signing_algorithm(UINT32 sign_alg, UINT32 digest_alg,
        TPM2B_PUBLIC *in_public) {

    if (sign_alg == TPM2_ALG_NULL) {
        sign_alg = TPM2_ALG_HMAC;
    }

    in_public->publicArea.parameters.keyedHashDetail.scheme.scheme = sign_alg;
    switch (sign_alg) {
    case TPM2_ALG_HMAC :
        in_public->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg =
                digest_alg;
        break;
    default:
        LOG_ERR(
                "The Keyedhash signing algorithm type input(%4.4x) is not supported!",
                sign_alg);
        return false;
    }

    return true;
}

static bool set_key_algorithm(TPM2B_PUBLIC *in_public, createak_context *ctx)
{
    in_public->publicArea.nameAlg = TPM2_ALG_SHA256;
    // First clear attributes bit field.
    in_public->publicArea.objectAttributes = 0;
    in_public->publicArea.objectAttributes &= ~TPMA_OBJECT_RESTRICTED;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_SIGN;
    in_public->publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
    in_public->publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    in_public->publicArea.authPolicy.size = 0;

    in_public->publicArea.type = ctx->ak.in.alg.type;

    switch(ctx->ak.in.alg.type)
    {
    case TPM2_ALG_RSA:  
        in_public->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        in_public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
        in_public->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_NULL;
        in_public->publicArea.parameters.rsaDetail.keyBits = 2048;
        in_public->publicArea.parameters.rsaDetail.exponent = 0;
        in_public->publicArea.unique.rsa.size = 0;
        return set_rsa_signing_algorithm(ctx->ak.in.alg.sign, ctx->ak.in.alg.digest, in_public);
    case TPM2_ALG_ECC:
        in_public->publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
        in_public->publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_NULL;
        in_public->publicArea.parameters.eccDetail.symmetric.keyBits.sym = 0;
        in_public->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        in_public->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        in_public->publicArea.unique.ecc.x.size = 0;
        in_public->publicArea.unique.ecc.y.size = 0;
        return set_ecc_signing_algorithm(ctx->ak.in.alg.sign, ctx->ak.in.alg.digest, in_public);
    case TPM2_ALG_KEYEDHASH:
        in_public->publicArea.unique.keyedHash.size = 0;
        return set_keyed_hash_signing_algorithm(ctx->ak.in.alg.sign, ctx->ak.in.alg.digest, in_public);
    case TPM2_ALG_SYMCIPHER:
    default:
        LOG_ERR("The algorithm type input(%4.4x) is not supported!", ctx->ak.in.alg.type);
        return false;
    }

    return true;
}

static bool __create_ak(TSS2_SYS_CONTEXT *sapi_context, createak_context *ctx) {

    TPML_PCR_SELECTION creation_pcr;
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    TSS2L_SYS_AUTH_COMMAND sessions_data = {1, {
        {
        .sessionHandle = TPM2_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = 0,
    }}};

    TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
    TPMT_TK_CREATION creation_ticket = TPMT_TK_CREATION_EMPTY_INIT;
    TPM2B_CREATION_DATA creation_data = TPM2B_EMPTY_INIT;

    TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);

    TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_DIGEST creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    inSensitive.sensitive.data.size = 0;
    inSensitive.size = inSensitive.sensitive.userAuth.size + 2;
    creation_pcr.count = 0;

    memcpy(&inSensitive.sensitive.userAuth, &ctx->ak.in.auth, sizeof(ctx->ak.in.auth));

    bool result = set_key_algorithm(&inPublic, ctx);
    if (!result) {
        return false;
    }

    memcpy(&sessions_data.auths[0].hmac, &ctx->ek.auth, sizeof(ctx->ek.auth));

    tpm2_session_data *data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session *session = tpm2_session_new(sapi_context, data);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(session);
    tpm2_session_free(&session);


    TPM2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(
            sapi_context,
            TPM2_RH_ENDORSEMENT,
            handle,
            &sessions_data,
            NULL,
            NULL,
            NULL,
            0,
            NULL,
            NULL,
            NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicySecret, rval);
        return false;
    }

    LOG_INFO("Tss2_Sys_PolicySecret succ");

    sessions_data.auths[0].sessionHandle = handle;
    sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_ContextLoad(sapi_context, &ctx->ek.context, &ctx->ek.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextLoad, rval);
        return false;
    }


    rval = TSS2_RETRY_EXP(Tss2_Sys_Create(sapi_context, ctx->ek.handle, &sessions_data,
            &inSensitive, &inPublic, &outsideInfo, &creation_pcr, &ctx->ak.out.priv,
            &ctx->ak.out.pub, &creation_data, &creation_hash, &creation_ticket,
            &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {  
        LOG_PERR(Tss2_Sys_Create, rval);
        return false;
    }
    LOG_INFO("TPM2_Create succ");

    // Need to flush the session here.
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }
    // And remove the session from sessions table.
    sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
    sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    memcpy(&sessions_data.auths[0].hmac, &ctx->ek.auth, sizeof(ctx->ek.auth));

    data = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!data) {
        LOG_ERR("oom");
        return false;
    }

    session = tpm2_session_new(sapi_context, data);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    LOG_INFO("tpm_session_start_auth_with_params succ");

    handle = tpm2_session_get_handle(session);
    tpm2_session_free(&session);

    rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(sapi_context, TPM2_RH_ENDORSEMENT,
            handle, &sessions_data, 0, 0, 0, 0, 0, 0, 0));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicySecret, rval);
        return false;
    }
    LOG_INFO("Tss2_Sys_PolicySecret succ");

    sessions_data.auths[0].sessionHandle = handle;
    sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_Load(sapi_context, ctx->ek.handle, &sessions_data, &ctx->ak.out.priv,
            &ctx->ak.out.pub, &ctx->ak.out.handle, &ctx->ak.out.name, &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Load, rval);
        return false;
    }


    rval = Tss2_Sys_ContextSave(sapi_context,ctx->ak.out.handle, &ctx->ak.context);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextSave, rval);
        return false;
    }


    // Need to flush the session here.
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }
    sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
    sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    // use the owner auth here.
    //memcpy(&sessions_data.auths[0].hmac, &ctx.owner.auth, sizeof(ctx.owner.auth));

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, ctx->ek.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, ctx->ak.out.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return false;
    }
    LOG_INFO("Flush transient AK succ.");
    
    return true;
}

#if 0

static int set_ak_alg_type(char *value) {
    ctx.ak.in.alg.type = tpm2_alg_util_from_optarg(value);
    if (ctx.ak.in.alg.type == TPM2_ALG_ERROR) {
        LOG_ERR("Could not convert algorithm. got: \"%s\".", value);
        return false;
    }
    return true;
}
static int set_ak_alg_digest(char *value) {
    ctx.ak.in.alg.digest = tpm2_alg_util_from_optarg(value);
    if (ctx.ak.in.alg.digest == TPM2_ALG_ERROR) {
        LOG_ERR("Could not convert digest algorithm.");
        return false;
    }
    return true;
}
static int set_ak_alg_sign(char *value) {
    ctx.ak.in.alg.sign = tpm2_alg_util_from_optarg(value);
    if (ctx.ak.in.alg.sign == TPM2_ALG_ERROR) {
        LOG_ERR("Could not convert signing algorithm.");
        return false;
    }
    return true;
}
#endif

int create_ak(TSS2_SYS_CONTEXT *sapi_context,createak_context *ctx) {

    //set_ak_alg_type(alg_type);
    //set_ak_alg_digest(alg_digest);
    //set_ak_alg_sign(alg_sign);

    return !__create_ak(sapi_context, ctx);
}
