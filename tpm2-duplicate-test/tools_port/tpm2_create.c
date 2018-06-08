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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_errata.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

#include "lib/log.h"
#include "tpm2_create.h"



int setup_alg(tpm_create_ctx *ctx)
{
    switch(ctx->nameAlg) {
    case TPM2_ALG_SHA1:
    case TPM2_ALG_SHA256:
    case TPM2_ALG_SHA384:
    case TPM2_ALG_SHA512:
    case TPM2_ALG_SM3_256:
    case TPM2_ALG_NULL:
        ctx->in_public.publicArea.nameAlg = ctx->nameAlg;
        break;
    default:
        LOG_ERR("nameAlg algorithm: 0x%0x not support !", ctx->nameAlg);
        return -1;
    }

    switch(ctx->in_public.publicArea.type) {
    case TPM2_ALG_RSA:
        ctx->in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        ctx->in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        ctx->in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
        ctx->in_public.publicArea.parameters.rsaDetail.exponent = 0;
        ctx->in_public.publicArea.unique.rsa.size = 0;
        break;

    case TPM2_ALG_KEYEDHASH:
        ctx->in_public.publicArea.unique.keyedHash.size = 0;
        ctx->in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
        if (ctx->flags.I) {
            // sealing
            ctx->in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN;
            ctx->in_public.publicArea.objectAttributes &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
            ctx->in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
        } else {
            // hmac
            ctx->in_public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN;
            ctx->in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
            ctx->in_public.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = ctx->nameAlg;  //for tpm2_hmac multi alg
        }
        break;

    case TPM2_ALG_ECC:
        ctx->in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
        ctx->in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
        ctx->in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        ctx->in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        ctx->in_public.publicArea.unique.ecc.x.size = 0;
        ctx->in_public.publicArea.unique.ecc.y.size = 0;
        break;

    case TPM2_ALG_SYMCIPHER:
        tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                          &ctx->in_public.publicArea.objectAttributes);

        ctx->in_public.publicArea.parameters.symDetail.sym.algorithm = TPM2_ALG_AES;
        ctx->in_public.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
        ctx->in_public.publicArea.parameters.symDetail.sym.mode.sym = TPM2_ALG_CFB;
        ctx->in_public.publicArea.unique.sym.size = 0;
        break;

    default:
        LOG_ERR("type algorithm: 0x%0x not support !", ctx->in_public.publicArea.type);
        return -2;
    }
    return 0;
}

int __create(TSS2_SYS_CONTEXT *sapi_context, tpm_create_ctx *ctx)
{
    TSS2_RC rval;
    TSS2L_SYS_AUTH_COMMAND sessionsData;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_PUBLIC            outPublic = TPM2B_EMPTY_INIT;
    TPM2B_PRIVATE           outPrivate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    TPM2B_CREATION_DATA     creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION        creationTicket = TPMT_TK_CREATION_EMPTY_INIT;

    sessionsData.count = 1;
    sessionsData.auths[0] = ctx->session_data;

    ctx->in_sensitive.size = ctx->in_sensitive.sensitive.userAuth.size + 2;

    if(setup_alg(ctx))
        return -1;

    creationPCR.count = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_ContextLoad(sapi_context, ctx->parent.context, &ctx->parent.handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextLoad, rval);
        return -5;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_Create(sapi_context, ctx->parent.handle, &sessionsData, &ctx->in_sensitive,
                           &ctx->in_public, &outsideInfo, &creationPCR, &ctx->out.priv, &ctx->out.pub,
                           &creationData, &creationHash, &creationTicket, &sessionsDataOut));
    if(rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Create, rval);
        return -2;
    }

    rval = Tss2_Sys_Load(sapi_context,
                        ctx->parent.handle,
                        &sessionsData,
                        &(ctx->out.priv),
                        &(ctx->out.pub),
                        &(ctx->out.handle),
                        &(ctx->out.name),
                        &sessionsDataOut);
    if(rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Load, rval);
        return -2;
    }

    rval = Tss2_Sys_ContextSave(sapi_context,ctx->out.handle, &ctx->context);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextSave, rval);
        return -3;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, ctx->out.handle));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return -4;    
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, ctx->parent.handle));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        return -5;    
    }

    return 0;
}


static bool set_ctx_parent_ctx(tpm_create_ctx *ctx, TPMS_CONTEXT *pctx) {
    
    if (pctx == NULL) {
        LOG_ERR("Invalid pctx");
        return false;
    }
    ctx->parent.context = pctx;

    ctx->flags.c = 1;
    return true;
}

static bool set_ctx_hash_alg(tpm_create_ctx *ctx, char *value) {

    ctx->nameAlg = tpm2_alg_util_from_optarg(value);
    if(ctx->nameAlg == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid hash algorithm, got\"%s\"", value);
        return false;
    }
    ctx->flags.g = 1;
    return true;
}

static bool set_ctx_key_alg(tpm_create_ctx *ctx, char *value) {

    ctx->in_public.publicArea.type = tpm2_alg_util_from_optarg(value);
    if(ctx->in_public.publicArea.type == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid key algorithm, got\"%s\"", value);
        return false;
    }

    ctx->flags.G = 1;
    return true;
}

static bool set_ctx_default_sensitive_data(tpm_create_ctx *ctx) {
    int i;
    for (i = 0; i < 8; i++) {
        ctx->in_sensitive.sensitive.data.buffer[i] = i;
    }
    ctx->in_sensitive.sensitive.data.size = 8;
    ctx->flags.I = 1;
    return true;
}

static bool set_ctx_policy(tpm_create_ctx *ctx, TPM2B_DIGEST *policy) {
    ctx->in_public.publicArea.authPolicy.size = policy->size;
    memcpy(ctx->in_public.publicArea.authPolicy.buffer, policy->buffer,
                                    policy->size);
    ctx->flags.L = 1;
    return true;
}


static bool load_sensitive(tpm_create_ctx *ctx) {

    ctx->in_sensitive.sensitive.data.size = BUFFER_SIZE(typeof(ctx->in_sensitive.sensitive.data), buffer);
    return files_load_bytes_from_file_or_stdin(ctx->input,
            &ctx->in_sensitive.sensitive.data.size, ctx->in_sensitive.sensitive.data.buffer);
}

int create(TSS2_SYS_CONTEXT *sapi_context, 
            char *key_alg,
            char *hash_alg,
            TPM2B_DIGEST *policy,
            TPMS_CONTEXT *pctx,
            tpm_create_ctx *ctx) {

    int returnVal = 0;
    int flagCnt = 0;

    set_ctx_parent_ctx(ctx, pctx);
    set_ctx_hash_alg(ctx, hash_alg);
    set_ctx_key_alg(ctx, key_alg);
    set_ctx_default_sensitive_data(ctx);
    set_ctx_policy(ctx, policy);
    if(ctx->flags.P == 0)
        ctx->session_data.hmac.size = 0;

    if (ctx->flags.I && ctx->in_public.publicArea.type != TPM2_ALG_KEYEDHASH) {
        LOG_ERR("Only TPM2_ALG_KEYEDHASH algorithm is allowed when sealing data");
        return 1;
    }

    flagCnt = ctx->flags.H + ctx->flags.g + ctx->flags.G + ctx->flags.c;
    if(flagCnt == 1) {
        return 1;
    } else if(flagCnt == 3 && (ctx->flags.H == 1 || ctx->flags.c == 1) &&
              ctx->flags.g == 1 && ctx->flags.G == 1) {

        if(returnVal == 0)
            returnVal = __create(sapi_context, ctx);

        if(returnVal)
            return 1;
    } else {
        return 1;
    }

    return 0;
}
