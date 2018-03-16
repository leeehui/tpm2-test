#ifndef TPM2_CREATEPOLICY_H
#define TPM2_CREATEPOLICY_H
#include "tpm2_session.h"

#include "tpm2_createak.h"

//Records the type of policy and if one is selected
typedef struct {
    bool PolicyPCR;
}policy_type;

//Common policy options
typedef struct tpm2_common_policy_options tpm2_common_policy_options;
struct tpm2_common_policy_options {
    tpm2_session *policy_session; // policy session
    TPM2_SE policy_session_type; // TPM2_SE_TRIAL or TPM2_SE_POLICY
    TPM2B_DIGEST policy_digest; // buffer to hold PolicyORed policy digest
    TPML_DIGEST policy_digest_list; // for policy OR/AND
    TPMI_ALG_HASH policy_digest_hash_alg; // hash alg of final policy digest
    //char *policy_file; // filepath for the policy digest
    //bool policy_file_flag; // if policy file input has been given
    //policy_type policy_type;
    //const char *context_file;  
    TPMT_TK_VERIFIED ticket;
};

//pcr policy options
typedef struct  tpm2_pcr_policy_options tpm2_pcr_policy_options;
struct tpm2_pcr_policy_options {
    char *raw_pcrs_file; // filepath of input raw pcrs file
    TPML_PCR_SELECTION pcr_selections; // records user pcr selection per setlist
};

//locality policy options
typedef struct  tpm2_locality_policy_options tpm2_locality_policy_options;
struct tpm2_locality_policy_options {
    TPMA_LOCALITY locality; // locality to be bound
    
};  


typedef struct create_policy_ctx create_policy_ctx;
struct create_policy_ctx {
    tpm2_common_policy_options common_policy_options;
    tpm2_pcr_policy_options pcr_policy_options;
    tpm2_locality_policy_options locality_policy_options;
};

#define TPM2_COMMON_POLICY_INIT { \
            .policy_session = NULL, \
            .policy_session_type = TPM2_SE_TRIAL, \
            .policy_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer), \
            .policy_digest_hash_alg = TPM2_ALG_SHA256, \
        }



int create_policy(TSS2_SYS_CONTEXT *sapi_context, 
                    createak_context *ak_ctx, 
                    create_policy_ctx *pctx) ;
                    
int start_policy(TSS2_SYS_CONTEXT *sapi_context,
                            TPM2_CC command_to_bind,
                            createak_context *ak_ctx, 
                            create_policy_ctx *pctx
                            ) ;

#endif
