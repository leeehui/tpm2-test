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
esys_create_ek(ESYS_CONTEXT * esys_context, TPMS_CONTEXT **context_ek, TPM2B_AUTH *authValueEk)
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
            .userAuth = {0},
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };
    inSensitivePrimary.sensitive.userAuth.size = authValueEk->size;
    memcpy(inSensitivePrimary.sensitive.userAuth.buffer, authValueEk->buffer, authValueEk->size);

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
esys_create_aik(ESYS_CONTEXT * esys_context, TPMS_CONTEXT *context_ek, TPM2B_AUTH *authValueEk, TPMS_CONTEXT **context_aik, TPM2B_AUTH *authValueAik)
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
            .userAuth = {0},
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };
    inSensitive.sensitive.userAuth.size = authValueAik->size;
    memcpy(inSensitive.sensitive.userAuth.buffer, authValueAik->buffer, authValueAik->size);

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

    r = Esys_TR_SetAuth(esys_context, ekHandle, authValueEk);
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
            LOG_ERROR("Cleanup aikHandle failed.");
        }
    }
    if (ekHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, ekHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup ekHandle failed.");
        }
    }

    return failure_return;

}

int
esys_create_srk(ESYS_CONTEXT * esys_context, TPMS_CONTEXT **context_srk, TPM2B_AUTH *authValueSrk)
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
                                 //TPMA_OBJECT_FIXEDTPM |
                                 //TPMA_OBJECT_FIXEDPARENT |
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
            .userAuth = {0},
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };
    inSensitivePrimary.sensitive.userAuth.size = authValueSrk->size;
    memcpy(inSensitivePrimary.sensitive.userAuth.buffer, authValueSrk->buffer, authValueSrk->size);

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

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error esys create primary", error);


    r = Esys_ContextSave(esys_context, primaryHandle, context_srk);
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
esys_create_policy(ESYS_CONTEXT *esys_context, TPMS_CONTEXT *context_aik, TPM2B_AUTH *authValueAik, 
                    TPM2B_DIGEST *policyAuthorizeDigest)
{
    TSS2_RC r;
    ESYS_TR aikHandle = ESYS_TR_NONE;
    ESYS_TR policySession = ESYS_TR_NONE;
    int failure_return = EXIT_FAILURE;

    /*
     * First the policy value to be able to use Esys_Duplicate for an object has to be
     * determined with a policy trial session.
     */
    ESYS_TR sessionTrial = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetricTrial = {.algorithm = TPM2_ALG_AES,
                                   .keyBits = {.aes = 128},
                                   .mode = {.aes = TPM2_ALG_CFB}
    };
    TPM2B_NONCE nonceCallerTrial = {
        .size = 20,
        .buffer = {11, 12, 13, 14, 15, 16, 17, 18, 19, 11,
                   21, 22, 23, 24, 25, 26, 27, 28, 29, 30}
    };

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session", error);

    r = Esys_PolicyCommandCode(esys_context,
                               sessionTrial,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               TPM2_CC_Duplicate
                               );
    goto_if_error(r, "Error: PolicyCommandCode", error);

    TPM2B_DIGEST *policyDigestTrial;
    r = Esys_PolicyGetDigest(esys_context,
                             sessionTrial,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &policyDigestTrial
                             );
    goto_if_error(r, "Error: PolicyGetDigest", error);


    /* load ak, read name, */
    r = Esys_ContextLoad(esys_context, context_aik, &aikHandle);
    goto_if_error(r, "Error esys context load", error);

    r = Esys_TR_SetAuth(esys_context, aikHandle, authValueAik);
    goto_if_error(r, "Error esys TR_SetAuth ", error);

    TPM2B_NAME *nameKeySign;
    TPM2B_NAME *keyQualifiedName;
    TPM2B_PUBLIC *outPublic;
    r = Esys_ReadPublic(esys_context,
                        aikHandle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &outPublic,
                        &nameKeySign,
                        &keyQualifiedName);
    goto_if_error(r, "Error: ReadPublic", error);

    /* Dummy data for first call of PolicyAuthorize */
    TPM2B_NONCE policyRef = {0};
    TPMT_TK_VERIFIED  checkTicket = {
        .tag = TPM2_ST_VERIFIED,
        .hierarchy = TPM2_RH_ENDORSEMENT,
        .digest = {0}
    };

    r = Esys_PolicyAuthorize(
        esys_context,
        sessionTrial,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        policyDigestTrial,
        &policyRef,
        nameKeySign,
        &checkTicket
        );
    goto_if_error(r, "Error: PolicyAuthorize", error);

    r = Esys_PolicyGetDigest(esys_context,
                             sessionTrial,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &policyAuthorizeDigest);
    goto_if_error(r, "Error: PolicyGetDigest", error);

    r = Esys_FlushContext(esys_context, sessionTrial);
    goto_if_error(r, "Error: FlushContext", error);


    r = Esys_FlushContext(esys_context, aikHandle);
    goto_if_error(r, "Error: FlushContext", error);

    return EXIT_SUCCESS;

 error:

    if (sessionTrial != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, sessionTrial) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup sessionTrial failed.");
        }
    }

    if (aikHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, aikHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup aikHandle failed.");
        }
    }

    return EXIT_FAILURE;
}

#if 0
int
esys_start_policy(ESYS_CONTEXT *esys_context, TPMS_CONTEXT *context_aik, TPM2B_AUTH authValueAik)
{
    TSS2_RC r;
    ESYS_TR aikHandle = ESYS_TR_NONE;
    ESYS_TR policySession = ESYS_TR_NONE;
    int failure_return = EXIT_FAILURE;

    /*
     * First the policy value to be able to use Esys_Duplicate for an object has to be
     * determined with a policy trial session.
     */
    ESYS_TR sessionTrial = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetricTrial = {.algorithm = TPM2_ALG_AES,
                                   .keyBits = {.aes = 128},
                                   .mode = {.aes = TPM2_ALG_CFB}
    };
    TPM2B_NONCE nonceCallerTrial = {
        .size = 20,
        .buffer = {11, 12, 13, 14, 15, 16, 17, 18, 19, 11,
                   21, 22, 23, 24, 25, 26, 27, 28, 29, 30}
    };

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCallerTrial,
                              TPM2_SE_TRIAL, &symmetricTrial, TPM2_ALG_SHA1,
                              &sessionTrial);
    goto_if_error(r, "Error: During initialization of policy trial session", error);

    r = Esys_PolicyCommandCode(esys_context,
                               sessionTrial,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               TPM2_CC_Duplicate
                               );
    goto_if_error(r, "Error: PolicyCommandCode", error);

    TPM2B_DIGEST *policyDigestTrial;
    r = Esys_PolicyGetDigest(esys_context,
                             sessionTrial,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &policyDigestTrial
                             );
    goto_if_error(r, "Error: PolicyGetDigest", error);


    /* load ak, read name, */
    r = Esys_ContextLoad(esys_context, context_aik, &aikHandle);
    goto_if_error(r, "Error esys context load", error);

    r = Esys_TR_SetAuth(esys_context, aikHandle, &authValueAik);
    goto_if_error(r, "Error esys TR_SetAuth ", error);

    TPM2B_NAME *nameKeySign;
    TPM2B_NAME *keyQualifiedName;
    TPM2B_PUBLIC *outPublic;
    r = Esys_ReadPublic(esys_context,
                        aikHandle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &outPublic,
                        &nameKeySign,
                        &keyQualifiedName);
    goto_if_error(r, "Error: ReadPublic", error);

    /* Dummy data for first call of PolicyAuthorize */
    TPM2B_NONCE policyRef = {0};
    TPMT_TK_VERIFIED  checkTicket = {
        .tag = TPM2_ST_VERIFIED,
        .hierarchy = TPM2_RH_ENDORSEMENT,
        .digest = {0}
    };

    r = Esys_PolicyAuthorize(
        esys_context,
        sessionTrial,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        policyDigestTrial,
        &policyRef,
        nameKeySign,
        &checkTicket
        );
    goto_if_error(r, "Error: PolicyAuthorize", error);

    r = Esys_PolicyGetDigest(esys_context,
                             sessionTrial,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &policyAuthorizeDigest);
    goto_if_error(r, "Error: PolicyGetDigest", error);

    r = Esys_FlushContext(esys_context, sessionTrial);
    goto_if_error(r, "Error: FlushContext", error);


    r = Esys_FlushContext(esys_context, aikHandle);
    goto_if_error(r, "Error: FlushContext", error);

    return EXIT_SUCCESS;

 error:

    if (sessionTrial != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, sessionTrial) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup sessionTrial failed.");
        }
    }

    if (aikHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, aikHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup aikHandle failed.");
        }
    }

    return EXIT_FAILURE;
}
#endif 

int
esys_create_sk(ESYS_CONTEXT *esys_context, TPMS_CONTEXT *context_p, TPM2B_AUTH *auth_p, 
                TPM2B_DIGEST *policy_digest, TPM2B_SENSITIVE_DATA *wrapping_key, TPMS_CONTEXT **context_sk, TPM2B_AUTH *auth_sk) 
{
    TSS2_RC r;
    ESYS_TR pHandle = ESYS_TR_NONE;
    ESYS_TR skHandle = ESYS_TR_NONE;
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

    /* sensitive template for creating */
    TPM2B_SENSITIVE_CREATE inSensitive;

    inSensitive.sensitive.data.size = wrapping_key->size;
    memcpy(inSensitive.sensitive.data.buffer, wrapping_key->buffer, wrapping_key->size);
    inSensitive.sensitive.userAuth.size = auth_sk->size;
    memcpy(inSensitive.sensitive.userAuth.buffer, auth_sk->buffer, auth_sk->size);

    TPM2B_TEMPLATE inPublic_template = {0};
    TPM2B_PRIVATE *outPrivate;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH ),
                                 //TPMA_OBJECT_DECRYPT),

            .authPolicy = {
                .size = 0,
             },
            .parameters.keyedHashDetail = {
                .scheme.scheme = TPM2_ALG_NULL,
             },
            .unique.keyedHash = {
                .size = 0,
            }
        }
    };

    inPublic.publicArea.authPolicy.size = policy_digest->size;
    memcpy(inPublic.publicArea.authPolicy.buffer, policy_digest->buffer, policy_digest->size);

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };


    r = Esys_ContextLoad(esys_context, context_p, &pHandle);
    goto_if_error(r, "Error esys context load", error);

    r = Esys_TR_SetAuth(esys_context, pHandle, auth_p);
    goto_if_error(r, "Error esys TR_SetAuth ", error);

    r = Esys_Create(esys_context,
                    pHandle,
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
                  pHandle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, outPrivate, outPublic, &skHandle);
    goto_if_error(r, "Error esys load ", error);

    r = Esys_ContextSave(esys_context, skHandle, context_sk);
    goto_if_error(r, "Error esys context save", error);

    r = Esys_FlushContext(esys_context, pHandle);
    goto_if_error(r, "Error esys flush context", error);

    r = Esys_FlushContext(esys_context, skHandle);
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

    if (pHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, pHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup pHandle failed.");
        }
    }
    if (skHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, skHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup skHandle failed.");
        }
    }

    return failure_return;
}

int
test_invoke_esapi(ESYS_CONTEXT * esys_context) {
    TSS2_RC r;

    /* saved EK(Endorsement Key) context */
    TPMS_CONTEXT *context_ek;
    TPM2B_AUTH authValueEk = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    /* saved AIK(Attestation Identification Key) context,
     * AIK is used as keySign parameter of PolicyAuthorize */
    TPMS_CONTEXT *context_aik;
    TPM2B_AUTH authValueAik = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    /* saved SRK(Storage Root Key) SRC context */
    TPMS_CONTEXT *context_srk_src;
    TPM2B_AUTH authValueSrkSrc = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    /* saved SRK(Storage Root Key) DES context */
    TPMS_CONTEXT *context_srk_des;
    TPM2B_AUTH authValueSrkDes = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPMS_CONTEXT *context_sk;
    TPM2B_AUTH authValueSk= {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    /* policy digest for creating SK(Storage Key) */
    TPM2B_DIGEST *policyAuthorizeDigest;

    /* the wrapping_key is data to be sealed into SK */
    TPM2B_SENSITIVE_DATA wrapping_key = {.size = 32};
    for (int i = 0; i < wrapping_key.size; i++) {
        wrapping_key.buffer[i] = i;
    }

    /* the unseal_data is data to unseal after duplication */
    TPM2B_SENSITIVE_DATA unseal_data = {0};

    LOG_INFO("start.");

    LOG_INFO("create ek.");
    r = esys_create_ek(esys_context, &context_ek, &authValueEk);
    LOG_INFO("create aik.");
    r = esys_create_aik(esys_context, context_ek, &authValueEk, &context_aik, &authValueAik);
    LOG_INFO("create srk_src.");
    r = esys_create_srk(esys_context, &context_srk_src, &authValueSrkSrc);
    LOG_INFO("create srk_des.");
    r = esys_create_srk(esys_context, &context_srk_des, &authValueSrkDes);
    LOG_INFO("create policy.");
    r = esys_create_policy(esys_context, context_aik, &authValueAik, policyAuthorizeDigest);
    LOG_INFO("create sk.");
    r = esys_create_sk(esys_context, context_srk_src, &authValueSrkSrc, 
                        policyAuthorizeDigest, &wrapping_key, &context_sk, &authValueSk);

    return r;
}
