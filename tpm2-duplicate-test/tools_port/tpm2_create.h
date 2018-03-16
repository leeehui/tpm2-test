#ifndef TPM2_CREATE_H
#define TPM2_CREATE_H

typedef struct tpm_create_ctx tpm_create_ctx;
struct tpm_create_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPM2B_SENSITIVE_CREATE in_sensitive;
    TPM2B_PUBLIC in_public;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    TPMS_CONTEXT context;
    struct {
        TPMI_DH_OBJECT handle; //used for temporarily saving parent handle
        TPMS_CONTEXT *context;
    } parent;

    struct {
        TPM2_HANDLE handle;
        TPM2B_NAME name;
        TPM2B_PUBLIC pub;
        TPM2B_PRIVATE priv;
    } out;

    char *input;

    struct {
        UINT16 H : 1;
        UINT16 P : 1;
        UINT16 K : 1;
        UINT16 g : 1;
        UINT16 G : 1;
        UINT16 A : 1;
        UINT16 I : 1;
        UINT16 L : 1;
        UINT16 u : 1;
        UINT16 c : 1;
        UINT16 r : 1;
    } flags;
};

#define PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT { \
    .publicArea = { \
        .objectAttributes = \
                  TPMA_OBJECT_DECRYPT|TPMA_OBJECT_SIGN \
                  |TPMA_OBJECT_SENSITIVEDATAORIGIN| \
                   TPMA_OBJECT_USERWITHAUTH \
    }, \
}


int create(TSS2_SYS_CONTEXT *sapi_context, 
            char *key_alg,
            char *hash_alg,
            TPM2B_DIGEST *policy,
            TPMS_CONTEXT *pctx,
            tpm_create_ctx *ctx);


#endif