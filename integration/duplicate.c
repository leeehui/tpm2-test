/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#include <stdlib.h>

#include "tss2_esys.h"
#include "tss2_mu.h"

#include "esys_iutil.h"
#include "test-esapi.h"
#define LOGMODULE test
#include "util/log.h"

/** This test is intended to test the ESAPI command CreateLoaded.
 *
 * We start by creating a primary key (Esys_CreatePrimary).
 * This primary key will be used as parent key for CreateLoaded.
 *
 * Tested ESAPI commands:
 *  - Esys_CreateLoaded() (F)
 *  - Esys_CreatePrimary() (M)
 *  - Esys_FlushContext() (M)
 *  - Esys_StartAuthSession() (M)
 *
 * Used compiler defines: TEST_SESSION
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */

int
esys_create_ek(ESYS_CONTEXT * esys_context, TPMS_CONTEXT **context_ek, TPM2B_AUTH authValueEk)
{

    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    int failure_return = EXIT_FAILURE;

#ifdef TEST_SESSION
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    memset(&sessionAttributes, 0, sizeof sessionAttributes);

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);

    goto_if_error(r, "Error: During initialization of session", error);
#endif /* TEST_SESSION */

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                      .scheme = TPM2_ALG_NULL
                  },
                 .keyBits = 2048,
                 .exponent = 0,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {},
             },
        },
    };


    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = authValueEk,
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_ENDORSEMENT, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error esys create primary", error);


    r = Esys_ContextSave(esys_context, primaryHandle, context_ek);
    goto_if_error(r, "Error esys context save", error);

    r = Esys_FlushContext(esys_context, primaryHandle);
    goto_if_error(r, "Error esys flush context", error);

#ifdef TEST_SESSION
    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error esys flush context", error);
#endif
    return EXIT_SUCCESS;

 error:

#ifdef TEST_SESSION
    if (session != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup session failed.");
        }
    }
#endif

    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    return failure_return;
}

int
esys_create_aik(ESYS_CONTEXT * esys_context, TPMS_CONTEXT *context_ek, TPM2B_AUTH authValueEk, TPMS_CONTEXT **context_aik, TPM2B_AUTH authValueAik)
{

    TSS2_RC r;
    ESYS_TR ekHandle = ESYS_TR_NONE;
    ESYS_TR aikHandle = ESYS_TR_NONE;
    int failure_return = EXIT_FAILURE;

#ifdef TEST_SESSION
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    memset(&sessionAttributes, 0, sizeof sessionAttributes);

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);

    goto_if_error(r, "Error: During initialization of session", error);
#endif /* TEST_SESSION */

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 4,
        .sensitive = {
            .userAuth = authValueAik,
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    TPM2B_TEMPLATE inPublic_template = {0};
    TPM2B_PRIVATE *outPrivate;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_RESTRICTED |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),

            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_AES,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB
                 },
                 .scheme = {
                      .scheme =
                      TPM2_ALG_NULL,
                  },
                 .keyBits = 2048,
                 .exponent = 0
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {}
                 ,
             }
        }
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };


    r = Esys_ContextLoad(esys_context, context_ek, &ekHandle);
    goto_if_error(r, "Error esys context load", error);

    r = Esys_TR_SetAuth(esys_context, ekHandle, &authValueEk);
    goto_if_error(r, "Error esys TR_SetAuth ", error);

    r = Esys_Create(esys_context,
                    ekHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive,
                    &inPublic,
                    &outsideInfo,
                    &creationPCR,
                    &outPrivate,
                    &outPublic,
                    &creationData, &creationHash, &creationTicket);
    goto_if_error(r, "Error esys second create ", error);

    r = Esys_Load(esys_context,
                  ekHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate, outPublic, &aikHandle);
    goto_if_error(r, "Error esys load ", error);

    r = Esys_ContextSave(esys_context, aikHandle, context_aik);
    goto_if_error(r, "Error esys context save", error);

    r = Esys_FlushContext(esys_context, aikHandle);
    goto_if_error(r, "Error esys flush context", error);

    r = Esys_FlushContext(esys_context, ekHandle);
    goto_if_error(r, "Error: FlushContext", error);

#ifdef TEST_SESSION
    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Error esys flush context", error);
#endif
    return EXIT_SUCCESS;

 error:

#ifdef TEST_SESSION
    if (session != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup session failed.");
        }
    }
#endif

    if (aikHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, aikHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }
    if (ekHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, ekHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    return failure_return;

}

int
test_invoke_esapi(ESYS_CONTEXT * esys_context) {
    TSS2_RC r;
    TPMS_CONTEXT *context_ek;
    TPM2B_AUTH authValueEk = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };
    TPMS_CONTEXT *context_aik;
    TPM2B_AUTH authValueAik = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };
    LOG_INFO("start.");
    LOG_INFO("create ek.");
    r = esys_create_ek(esys_context, &context_ek, authValueEk);
    LOG_INFO("create aik.");
    r = esys_create_aik(esys_context, context_ek, authValueEk, &context_aik, authValueAik);
    return r;
}
