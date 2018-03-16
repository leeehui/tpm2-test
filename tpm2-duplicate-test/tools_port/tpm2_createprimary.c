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
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

#include "lib/log.h"
#include "tpm2_createprimary.h"

static bool set_name_alg(TPMI_ALG_HASH halg, TPM2B_PUBLIC *public) {

    switch(halg) {
    case TPM2_ALG_SHA1:
    case TPM2_ALG_SHA256:
    case TPM2_ALG_SHA384:
    case TPM2_ALG_SHA512:
    case TPM2_ALG_SM3_256:
    case TPM2_ALG_NULL:
        public->publicArea.nameAlg = halg;
        return true;
    }

    LOG_ERR("name algorithm \"%s\" not supported!",
            tpm2_alg_util_algtostr(halg));

    return false;
}

static bool set_alg(TPMI_ALG_PUBLIC type, TPM2B_PUBLIC *public) {


    switch(type) {
    case TPM2_ALG_RSA: {
        TPMS_RSA_PARMS *r = &public->publicArea.parameters.rsaDetail;
       r->symmetric.algorithm = TPM2_ALG_AES;
       r->symmetric.keyBits.aes = 128;
       r->symmetric.mode.aes = TPM2_ALG_CFB;
       r->scheme.scheme = TPM2_ALG_NULL;
       r->keyBits = 2048;
       r->exponent = 0;
       public->publicArea.unique.rsa.size = 0;
    } break;
    case TPM2_ALG_KEYEDHASH: {
        TPMT_KEYEDHASH_SCHEME *s = &public->publicArea.parameters.keyedHashDetail.scheme;
       s->scheme = TPM2_ALG_XOR;
       s->details.exclusiveOr.hashAlg = TPM2_ALG_SHA256;
       s->details.exclusiveOr.kdf = TPM2_ALG_KDF1_SP800_108;
       public->publicArea.unique.keyedHash.size = 0;
    } break;
    case TPM2_ALG_ECC: {
        TPMS_ECC_PARMS *e = &public->publicArea.parameters.eccDetail;
       e->symmetric.algorithm = TPM2_ALG_AES;
       e->symmetric.keyBits.aes = 128;
       e->symmetric.mode.sym = TPM2_ALG_CFB;
       e->scheme.scheme = TPM2_ALG_NULL;
       e->curveID = TPM2_ECC_NIST_P256;
       e->kdf.scheme = TPM2_ALG_NULL;
       public->publicArea.unique.ecc.x.size = 0;
       public->publicArea.unique.ecc.y.size = 0;
    } break;
    case TPM2_ALG_SYMCIPHER: {
        TPMS_SYMCIPHER_PARMS *s = &public->publicArea.parameters.symDetail;
       s->sym.algorithm = TPM2_ALG_AES;
       s->sym.keyBits.sym = 128;
       s->sym.mode.sym = TPM2_ALG_CFB;
       public->publicArea.unique.sym.size = 0;
    } break;
    default:
        LOG_ERR("type algorithm \"%s\" not supported!",
                tpm2_alg_util_algtostr(public->publicArea.type));

        return false;
    }

    public->publicArea.type = type;

    return true;
}



static bool set_ctx_hierarchy(tpm_createprimary_ctx *ctx, char *value) {
    bool res = tpm2_hierarchy_from_optarg(value, &ctx->objdata.in.hierarchy,
            TPM2_HIERARCHY_FLAGS_ALL);
    if (!res) {
        return false;
    }
    ctx->flags.H = 1;
    return true;
}

static bool set_ctx_hash_alg(tpm_createprimary_ctx *ctx, char *value) {
    TPMI_ALG_HASH halg = tpm2_alg_util_from_optarg(value);
    if (halg == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid hash algorithm, got\"%s\"", value);
        return false;
    }
    bool res = set_name_alg(halg, &ctx->objdata.in.public);
    if (!res) {
        return false;
    }
    ctx->flags.g = 1;

    return true;
}

static bool set_ctx_key_alg(tpm_createprimary_ctx *ctx, char *value) {
    TPMI_ALG_PUBLIC type = tpm2_alg_util_from_optarg(value);
    if (type == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid key algorithm, got\"%s\"", value);
        return false;
    }

    bool res = set_alg(type, &ctx->objdata.in.public);
    if (!res) {
        return false;
    }
    ctx->flags.G = 1;
    return true;
}

static bool set_ctx_passwd(tpm_createprimary_ctx *ctx, char *value){
    bool res = tpm2_password_util_from_optarg(value,
            &ctx->objdata.in.sensitive.sensitive.userAuth);
    if (!res) {
        LOG_ERR("Invalid new key password, got\"%s\"", value);
        return false;
    }
    return true;
}


static bool save_context_flush(TSS2_SYS_CONTEXT *sapi_context, tpm_createprimary_ctx *ctx) {
    TSS2_RC rval = Tss2_Sys_ContextSave(sapi_context,ctx->objdata.out.handle, &ctx->context);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextSave, rval);
        return false;
    }

    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, ctx->objdata.out.handle));
        if (rval != TSS2_RC_SUCCESS) {
            LOG_PERR(Tss2_Sys_FlushContext, rval);
            return false;    
    }

    return true;

}


static inline bool valid_ctx(tpm_createprimary_ctx *ctx) {
    return (ctx->flags.H && ctx->flags.g && ctx->flags.G);
}

int create_primary(TSS2_SYS_CONTEXT *sapi_context, 
                    char *hierarchy,
                    char *key_alg,
                    char *hash_alg,
                    tpm_createprimary_ctx *ctx) {
    
    set_ctx_hierarchy(ctx, hierarchy);
    set_ctx_key_alg(ctx, key_alg);
    set_ctx_hash_alg(ctx, hash_alg);

    if (!valid_ctx(ctx)) {
        return 1;
    }

    bool result = tpm2_hierarrchy_create_primary(sapi_context, &ctx->session_data, &ctx->objdata);
    if (!result) {
        return 1;
    }

    result = save_context_flush(sapi_context, ctx);
    if (!result) {
        return 1;
    }

    /* 0 on success, 1 otherwise */
    return !result;
}
