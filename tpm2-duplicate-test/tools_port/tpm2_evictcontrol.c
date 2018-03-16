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
#include <ctype.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "log.h"
#include "tpm2_ctx_mgmt.h"
#include "tpm2_hierarchy.h"
#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct tpm_evictcontrol_ctx tpm_evictcontrol_ctx;
struct tpm_evictcontrol_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPMI_RH_PROVISION auth;
    struct {
        TPMI_DH_OBJECT object;
        TPMI_DH_PERSISTENT persist;
    } handle;
    char *context_file;
    struct {
        UINT8 H : 1;
        UINT8 p : 1;
        UINT8 c : 1;
        UINT8 P : 1;
    } flags;
};

static tpm_evictcontrol_ctx ctx = {
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    .auth = TPM2_RH_OWNER,
};

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'A':
        result = tpm2_hierarchy_from_optarg(value, &ctx.auth,
                TPM2_HIERARCHY_FLAGS_O|TPM2_HIERARCHY_FLAGS_P);
        if (!result) {
            return false;
        }
        break;
    case 'H':
        result = tpm2_util_string_to_uint32(value, &ctx.handle.object);
        if (!result) {
            LOG_ERR("Could not convert object handle to a number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.flags.H = 1;

        if (ctx.handle.object >> TPM2_HR_SHIFT == TPM2_HT_PERSISTENT) {
            ctx.handle.persist = ctx.handle.object;
            ctx.flags.p = 1;
        }
        break;
    case 'p':
        result = tpm2_util_string_to_uint32(value, &ctx.handle.persist);
        if (!result) {
            LOG_ERR("Could not convert persistent handle to a number, got: \"%s\"",
                    value);
            return false;
        }
        ctx.flags.p = 1;
        break;
    case 'P':
        result = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
        if (!result) {
            LOG_ERR("Invalid authorization password, got\"%s\"", value);
            return false;
        }
        ctx.flags.P = 1;
        break;
    case 'c':
        ctx.context_file = value;
        ctx.flags.c = 1;
        break;
    case 'S':
        if (!tpm2_util_string_to_uint32(value, &ctx.session_data.sessionHandle)) {
            LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    }

    return  true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth",                 required_argument, NULL, 'A' },
      { "handle",               required_argument, NULL, 'H' },
      { "persistent",           required_argument, NULL, 'p' },
      { "pwda",                 required_argument, NULL, 'P' },
      { "context",              required_argument, NULL, 'c' },
      { "session",              required_argument, NULL, 'S' },
    };

    ctx.session_data.sessionHandle = TPM2_RS_PW;

    *opts = tpm2_options_new("A:H:p:P:c:S:", ARRAY_LEN(topts), topts, on_option,
                             NULL, TPM2_OPTIONS_SHOW_USAGE);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);

    if (!((ctx.flags.H || ctx.flags.c) && ctx.flags.p)) {
        LOG_ERR("Invalid arguments, expect (-H or -c) and -p");
        return 1;
    }

    if (ctx.flags.c) {
        bool result = files_load_tpm_context_from_path(sapi_context, &ctx.handle.object,
                                                       ctx.context_file);
        if (!result) {
            return 1;
        }
    }

    tpm2_tool_output("persistentHandle: 0x%x\n", ctx.handle.persist);

    return !tpm2_ctx_mgmt_evictcontrol(sapi_context,
            ctx.auth,
            &ctx.session_data,
            ctx.handle.object,
            ctx.handle.persist);
}
