#include <inttypes.h>


//#define LOGLEVEL 0
#define LOGDEFAULT LOGLEVEL_TRACE

#define LOGMODULE duplicate-test
#include "log.h"
//#include "sapi-util.h"

#include "tpm2_createek.h"
#include "tpm2_createak.h"
#include "tpm2_createprimary.h"
#include "tpm2_create.h"
#include "tpm2_createpolicy.h"
#include "tpm2_duplicate.h"
#include "tpm2_util.h"


/* endorsement primary key */
static createek_context ek_ctx = {
    .passwords = {
        .owner = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
        .endorse = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
        .ek = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    },
    .objdata = TPM2_HIERARCHY_DATA_INIT
};

/* AIK */
static createak_context ak_ctx = {
    .ak = {
        .in = {
            .auth = TPM2B_EMPTY_INIT,
            .alg = {
                .type = TPM2_ALG_RSA,
                .digest = TPM2_ALG_SHA256,
                .sign = TPM2_ALG_NULL
            },
        },
        .out = {
            .priv = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer),
            .pub = TPM2B_EMPTY_INIT
        }
    },
    .ek = {
        .auth = TPM2B_EMPTY_INIT
    },
    .owner = {
        .auth = TPM2B_EMPTY_INIT
    },
};


/* srk_src storage root key of source server */
static tpm_createprimary_ctx srk_src_ctx = {
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    .objdata = TPM2_HIERARCHY_DATA_INIT
};



/* srk_des storage root key of destination server */
static tpm_createprimary_ctx srk_des_ctx = {
    .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    .objdata = TPM2_HIERARCHY_DATA_INIT
};

/* type KEYEDHASH storage key for sealing KWK */
static tpm_create_ctx sk_ctx = {
    .session_data = {
        .sessionHandle = TPM2_RS_PW,
        .sessionAttributes = 0,
    },
    .type = TPM2_ALG_SHA256,
    .nameAlg = TPM2_ALG_RSA,
    .in_public = PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT
};

/*
static tpm2_startauthsession_ctx authsession_ctx = {
    .session = {
        .type = TPM2_SE_TRIAL,
        .halg = TPM2_ALG_SHA256
    }
};
*/
static create_policy_ctx pctx = {
    .common_policy_options = TPM2_COMMON_POLICY_INIT,
    .locality_policy_options = {
        .locality = TPMA_LOCALITY_TPM2_LOC_THREE
    },
};


TSS2_RC set_cmd_locality( TSS2_SYS_CONTEXT *sapi_context, UINT8 locality )
{
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *tcti_context;

     rval = Tss2_Sys_GetTctiContext(sapi_context, &tcti_context);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_INFO("get tcti context failed: 0x%x", rval);
        return false;
    }

    rval = Tss2_Tcti_SetLocality(tcti_context, (UINT8)locality);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_INFO("Tss2_Tcti_SetLocality failed: 0x%x", rval);
        return false;
    }

    return rval;
}




int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    int res = 0;
    TPM2B_SENSITIVE_DATA unseal_data = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_DATA, buffer);
	LOG_INFO ("test invoke.");

    //set_cmd_locality(sapi_context, 1);
#if 1

    /* create EK(endorsement key) */
    res = create_ek(sapi_context, "rsa", &ek_ctx);
    if (!res) {
        LOG_INFO ("ek temp handle : 0x%x ", ek_ctx.objdata.out.handle);
    }

    /* create AIK(attestation indentity key), used as keySign in PolicyAuthorize*/
    ak_ctx.ek.context = ek_ctx.context;
    res = create_ak(sapi_context,  &ak_ctx);
    if (!res) {
        LOG_INFO ("ak temp handle : 0x%x ", ak_ctx.ak.out.handle);
        LOGBLOB_INFO(ak_ctx.ak.out.name.name, ak_ctx.ak.out.name.size, "Name:");
    }

  
    res = create_primary(sapi_context, "o", "rsa", "sha256", &srk_src_ctx);
    if (!res) {
        LOG_INFO ("srk_src temp handle : 0x%x ", srk_src_ctx.objdata.out.handle);
    }

    res = create_primary(sapi_context, "o", "rsa", "sha256", &srk_des_ctx);
    if (!res) {
        LOG_INFO ("srk_des temp handle : 0x%x", srk_des_ctx.objdata.out.handle);
    }

    
    res = create_policy(sapi_context, &ak_ctx, &pctx);
    if (!res) {
        LOG_INFO ("policy created");
    }

    res = create(sapi_context, "keyedhash", "sha256", &pctx.common_policy_options.policy_digest, &srk_src_ctx.context, &sk_ctx);
    if (!res) {
        LOG_INFO ("sk temp handle : 0x%x ", sk_ctx.out.handle);
    }

    pctx.common_policy_options.policy_session_type = TPM2_SE_POLICY;
    res = start_policy(sapi_context, TPM2_CC_Duplicate, &ak_ctx, &pctx);
    if (!res) {
        LOG_INFO ("duplicate policy started");
    }

    res = do_duplicate_import(sapi_context, 
                        &srk_src_ctx,
                        &srk_des_ctx,
                        &sk_ctx,
                        &ak_ctx,
                        &pctx
                        );
    if (!res) {
        LOG_INFO ("do_duplicate_import ok");
    }

    res = start_policy(sapi_context, TPM2_CC_Unseal, &ak_ctx, &pctx);
    if (!res) {
        LOG_INFO ("unseal policy started");
    }

    set_cmd_locality(sapi_context, 3);

    res = unseal(sapi_context,&sk_ctx, &pctx, &unseal_data);
    if (!res) {
        LOG_INFO ("unseal ok");
    }
    LOGBLOB_INFO(unseal_data.buffer, unseal_data.size, "Secret:");
#endif

	return res;	
}


