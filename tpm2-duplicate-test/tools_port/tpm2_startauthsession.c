//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
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

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "lib/log.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_startauthsession.h"


static bool set_session_halg(tpm2_startauthsession_ctx *ctx, char *value) {
    ctx.session.halg = tpm2_alg_util_from_optarg(value);
    if(ctx.session.halg == TPM2_ALG_ERROR) {
        LOG_ERR("Invalid choice for policy digest hash algorithm");
        return false;
    }
    return true;
}

int start_authsession(TSS2_SYS_CONTEXT *sapi_context,
                        TPM2_SE type,
                        char * halg,
                        tpm2_startauthsession_ctx *ctx) {

    int rc = 1;
    set_session_halg(halg);
    
    tpm2_session_data *session_data = tpm2_session_data_new(ctx->session.type);
    if (!session_data) {
        LOG_ERR("oom");
        return rc;
    }

    tpm2_session_set_authhash(session_data, ctx.session.halg);

    tpm2_session *s = tpm2_session_new(sapi_context,
            session_data);
    if (!s) {
        return rc;
    }

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(s);
    tpm2_tool_output("session-handle: 0x%" PRIx32 "\n", handle);

    TSS2_RC rval = Tss2_Sys_ContextSave(sysContext, handle, &ctx->output.context);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ContextSave, rval);
        return false;
    }

    rc = 0;

out:
    tpm2_session_free(&s);

    return rc;
}
