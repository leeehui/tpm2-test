
#ifndef TPM2_STARTAUTHSESSION_H
#define TPM2_STARTAUTHSESSION_H


typedef struct tpm2_startauthsession_ctx tpm2_startauthsession_ctx;
struct tpm2_startauthsession_ctx {
    struct {
        TPM2_SE type;
        TPMI_ALG_HASH halg;
    } session;
    struct {
        TPMS_CONTEXT context;
    } output;
};



#endif
