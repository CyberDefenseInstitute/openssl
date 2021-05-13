/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/x509v3.h>

typedef enum {
  X509_ACERT_DIGEST_PUBLIC_KEY,
  X509_ACERT_DIGEST_PUBLIC_KEY_CERT,
  X509_ACERT_DIGEST_OTHER,        /* must not be used in v2 */
} X509_ACERT_DIGEST_OBJECT_TYPE;

struct x509_acert_digest_info_st {
    X509_ACERT_DIGEST_OBJECT_TYPE digestObjectType;  /* ENUMERATED */
    ASN1_OBJECT *otherObjectTypeID;
    X509_ALGOR *digestAlgorithm;
    ASN1_BIT_STRING *objectDigest;
};

struct IssueSerial_st {
    GENERAL_NAMES *issuer;
    ASN1_INTEGER serial;
    ASN1_BIT_STRING *issuerUID;
};

struct ACertIssuer_v2Form_st {
    GENERAL_NAMES *issuerName;
    ISSUER_SERIAL *baseCertificateId;
    OBJECT_DIGEST_INFO *objectDigestInfo;
};

struct ACertIssuer_st {
    int type;
    union {
        GENERAL_NAMES *v1Form;
        ACERT_ISSUER_V2FORM *v2Form;
    } u;
};

struct Holder_st {
        ISSUER_SERIAL *baseCertificateID;
        GENERAL_NAMES *entityName;
        OBJECT_DIGEST_INFO *objectDigestInfo;
};

struct x509ACertInfo_st {
    ASN1_INTEGER version;      /* default of v2 */
    HOLDER holder;
    ACERT_ISSUER issuer;
    X509_ALGOR signature;
    ASN1_INTEGER serialNumber;
    X509_ACERT_VAL validityPeriod;
    STACK_OF(X509_ATTRIBUTE) *attributes;
    ASN1_BIT_STRING issuerUID;
    X509_EXTENSIONS *extensions;
};

struct x509ACert_st {
    X509_ACERT_INFO *acinfo;
    X509_ALGOR sig_alg;
    ASN1_BIT_STRING signature;
};

DECLARE_ASN1_ITEM(X509_ACERT_INFO)
DECLARE_ASN1_ITEM(HOLDER)
DECLARE_ASN1_ITEM(OBJECT_DIGEST_INFO)
DECLARE_ASN1_ITEM(ISSUER_SERIAL)
DECLARE_ASN1_ITEM(ACERT_ISSUER)
DECLARE_ASN1_ITEM(ACERT_ISSUER_V2FORM)
