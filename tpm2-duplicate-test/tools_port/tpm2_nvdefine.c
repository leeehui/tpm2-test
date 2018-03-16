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

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "tpm2_attr_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_nvdefine_ctx tpm_nvdefine_ctx;
struct tpm_nvdefine_ctx {
    UINT32 nvIndex;
    TPMI_RH_PROVISION auth;
    UINT16 size;
    TPMA_NV nvAttribute;
    TPM2B_AUTH nvAuth;
    TPMS_AUTH_COMMAND session_data;
    char *policy_file;
};

static tpm_nvdefine_ctx ctx = {
    .auth = TPM2_RH_PLATFORM,
    .nvAttribute = 0,
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    .nvAuth = TPM2B_EMPTY_INIT,
    .size = TPM2_MAX_NV_BUFFER_SIZE,
};

static int nv_space_define(TSS2_SYS_CONTEXT *sapi_context) {

    TPM2B_NV_PUBLIC public_info = TPM2B_EMPTY_INIT;

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    TSS2L_SYS_AUTH_COMMAND sessions_data = { 1, { ctx.session_data }};

    public_info.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH)
            + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);
    public_info.nvPublic.nvIndex = ctx.nvIndex;
    public_info.nvPublic.nameAlg = TPM2_ALG_SHA256;

    // Now set the attributes.
    public_info.nvPublic.attributes = ctx.nvAttribute;

    if (!ctx.size) {
        LOG_WARN("Defining an index with size 0");
    }

    if (ctx.policy_file) {
        public_info.nvPublic.authPolicy.size  = BUFFER_SIZE(TPM2B_DIGEST, buffer);
        if(!files_load_bytes_from_path(ctx.policy_file, public_info.nvPublic.authPolicy.buffer, &public_info.nvPublic.authPolicy.size )) {
            return false;
        }
    } 

    public_info.nvPublic.dataSize = ctx.size;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_NV_DefineSpace(sapi_context, ctx.auth,
            &sessions_data, &ctx.nvAuth, &public_info, &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_ERR("Failed to define NV area at index 0x%X", ctx.nvIndex);
        LOG_PERR(Tss2_Sys_NV_DefineSpace, rval);
        return false;
    }

    LOG_INFO("Success to define NV area at index 0x%x (%d).", ctx.nvIndex, ctx.nvIndex);

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'x':
        result = tpm2_util_string_to_uint32(value, &ctx.nvIndex);
        if (!result) {
            LOG_ERR("Could not convert NV index to number, got: \"%s\"",
                    value);
            return false;
        }

        if (ctx.nvIndex == 0) {
                LOG_ERR("NV Index cannot be 0");
                return false;
        }
        break;
    case 'a':
        result = tpm2_hierarchy_from_optarg(value, &ctx.auth,
                TPM2_HIERARCHY_FLAGS_O|TPM2_HIERARCHY_FLAGS_P);
        if (!result) {
            LOG_ERR("get h failed");
            return false;
        }
        break;
        case 'P':
            result = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
            if (!result) {
                LOG_ERR("Invalid handle password, got\"%s\"", value);
                return false;
            }
            break;
    case 's':
        result = tpm2_util_string_to_uint16(value, &ctx.size);
        if (!result) {
            LOG_ERR("Could not convert size to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 't':
        result = tpm2_util_string_to_uint32(value, &ctx.nvAttribute);
        if (!result) {
            result = tpm2_attr_util_nv_strtoattr(value, &ctx.nvAttribute);
            if (!result) {
                LOG_ERR("Could not convert NV attribute to number or keyword, got: \"%s\"",
                        value);
                return false;
            }
        }
        break;
    case 'I':
        result = tpm2_password_util_from_optarg(value, &ctx.nvAuth);
        if (!result) {
            LOG_ERR("Invalid index password, got\"%s\"", value);
            return false;
        }
        break;
    case 'L':
        ctx.policy_file = value;
        break;
    case 'S': {
        tpm2_session *s = tpm2_session_restore(value);
        if (!s) {
            return false;
        }

        ctx.session_data.sessionHandle = tpm2_session_get_handle(s);
        tpm2_session_free(&s);
    } break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "index",                  required_argument,  NULL,   'x' },
        { "auth-handle",            required_argument,  NULL,   'a' },
        { "size",                   required_argument,  NULL,   's' },
        { "attribute",              required_argument,  NULL,   't' },
        { "handle-passwd",          required_argument,  NULL,   'P' },
        { "index-passwd",           required_argument,  NULL,   'I' },
        { "passwdInHex",            no_argument,        NULL,   'X' },
        { "policy-file",            required_argument,  NULL,   'L' },
        { "session",                required_argument,  NULL,   'S' },
    };

    *opts = tpm2_options_new("x:a:s:t:P:I:rwdL:S:X", ARRAY_LEN(topts), topts,
                             on_option, NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    return nv_space_define(sapi_context) != true;
}
