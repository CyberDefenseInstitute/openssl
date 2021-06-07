/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "x509_acert.h"

ASN1_SEQUENCE(OBJECT_DIGEST_INFO) = {
    ASN1_EMBED(OBJECT_DIGEST_INFO, digestObjectType, ASN1_ENUMERATED),
    ASN1_OPT(OBJECT_DIGEST_INFO, otherObjectTypeID, ASN1_OBJECT),
    ASN1_SIMPLE(OBJECT_DIGEST_INFO, digestAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(OBJECT_DIGEST_INFO, objectDigest, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(OBJECT_DIGEST_INFO)

ASN1_SEQUENCE(ISSUER_SERIAL) = {
    ASN1_SEQUENCE_OF_OPT(ISSUER_SERIAL, issuer, GENERAL_NAME),
    ASN1_EMBED(ISSUER_SERIAL, serial, ASN1_INTEGER),
    ASN1_OPT(ISSUER_SERIAL, issuerUID, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(ISSUER_SERIAL)

ASN1_SEQUENCE(ACERT_ISSUER_V2FORM) = {
    ASN1_SEQUENCE_OF_OPT(ACERT_ISSUER_V2FORM, issuerName, GENERAL_NAME),
    ASN1_IMP_OPT(ACERT_ISSUER_V2FORM, baseCertificateId, ISSUER_SERIAL, 0),
    ASN1_IMP_OPT(ACERT_ISSUER_V2FORM, objectDigestInfo, OBJECT_DIGEST_INFO, 1),
} ASN1_SEQUENCE_END(ACERT_ISSUER_V2FORM)

ASN1_CHOICE(ACERT_ISSUER) = {
    ASN1_SEQUENCE_OF(ACERT_ISSUER, u.v1Form, GENERAL_NAME),
    ASN1_IMP(ACERT_ISSUER, u.v2Form, ACERT_ISSUER_V2FORM, 0),
} ASN1_CHOICE_END(ACERT_ISSUER)

ASN1_SEQUENCE(HOLDER) = {
    ASN1_IMP_OPT(HOLDER, baseCertificateID, ISSUER_SERIAL, 0),
    ASN1_IMP_SEQUENCE_OF_OPT(HOLDER, entityName, GENERAL_NAME, 1),
    ASN1_IMP_OPT(HOLDER, objectDigestInfo, OBJECT_DIGEST_INFO, 2),
} ASN1_SEQUENCE_END(HOLDER)

ASN1_SEQUENCE(X509_ACERT_INFO) = {
    ASN1_EMBED(X509_ACERT_INFO, version, ASN1_INTEGER),
    ASN1_EMBED(X509_ACERT_INFO, holder, HOLDER),
    ASN1_EMBED(X509_ACERT_INFO, issuer, ACERT_ISSUER),
    ASN1_EMBED(X509_ACERT_INFO, signature, X509_ALGOR),
    ASN1_EMBED(X509_ACERT_INFO, serialNumber, ASN1_INTEGER),
    ASN1_EMBED(X509_ACERT_INFO, validityPeriod, X509_ACERT_VAL),
    ASN1_SEQUENCE_OF(X509_ACERT_INFO, attributes, X509_ATTRIBUTE),
    ASN1_OPT(X509_ACERT_INFO, issuerUID, ASN1_BIT_STRING),
    ASN1_SEQUENCE_OF_OPT(X509_ACERT_INFO, extensions, X509_EXTENSION),
} ASN1_SEQUENCE_END(X509_ACERT_INFO)

ASN1_SEQUENCE(X509_ACERT) = {
    ASN1_SIMPLE(X509_ACERT, acinfo, X509_ACERT_INFO),
    ASN1_EMBED(X509_ACERT, sig_alg, X509_ALGOR),
    ASN1_EMBED(X509_ACERT, signature, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(X509_ACERT)

IMPLEMENT_ASN1_FUNCTIONS(X509_ACERT)

long X509_ACERT_get_version(const X509_ACERT *x)
{
    return ASN1_INTEGER_get(&x->acinfo->version);
}

void X509_ACERT_get0_signature(const X509_ACERT *x,
                               const ASN1_BIT_STRING **psig,
                               const X509_ALGOR **palg)
{
    if (*psig)
        *psig = &x->signature;
    if (*palg)
        *palg = &x->sig_alg;
}

static X509_NAME *get_dirName(const GENERAL_NAMES *names)
{
        GENERAL_NAME *dirName;
        if (sk_GENERAL_NAME_num(names) != 1)
            return NULL;

        dirName = sk_GENERAL_NAME_value(names, 0);
        if (dirName->type != GEN_DIRNAME)
            return NULL;

        return dirName->d.directoryName;
}

const X509_NAME *X509_ACERT_get0_holder_entityName(const X509_ACERT *x)
{
        return get_dirName(x->acinfo->holder.entityName);
}

void X509_ACERT_get0_holder_baseCertId(X509_NAME **issuer,
                                       ASN1_INTEGER **serial,
                                       ASN1_BIT_STRING **uid,
                                       const X509_ACERT *x)
{
    ISSUER_SERIAL *baseCertId = x->acinfo->holder.baseCertificateID;
    if (!baseCertId)
        return;

    if (issuer)
        *issuer = get_dirName(baseCertId->issuer);

    if (serial)
        *serial = &baseCertId->serial;

    if (uid)
        *uid = baseCertId->issuerUID;
}

void X509_ACERT_get0_holder_digest(int type, X509_ALGOR **digestAlgorithm,
                                   ASN1_BIT_STRING **digest,
                                   const X509_ACERT *x)
{
    OBJECT_DIGEST_INFO *digestInfo = x->acinfo->holder.objectDigestInfo;
    if (!digestInfo) {
        return;
    }

    if (digestAlgorithm)
        *digestAlgorithm = digestInfo->digestAlgorithm;
    if (*digest)
        *digest = digestInfo->objectDigest;
}

const X509_NAME *X509_ACERT_get0_issuerName( const X509_ACERT *x)
{
    return get_dirName(x->acinfo->issuer.u.v2Form->issuerName);
}

X509_ALGOR *X509_ACERT_get0_info_signature(const X509_ACERT *x)
{
    return &x->acinfo->signature;
}

ASN1_INTEGER *X509_ACERT_get_serialNumber(X509_ACERT *x)
{
    return &x->acinfo->serialNumber;
}

const ASN1_GENERALIZEDTIME *X509_ACERT_get0_notBefore(const X509_ACERT *x)
{
    return x->acinfo->validityPeriod.notBefore;
}

const ASN1_GENERALIZEDTIME *X509_ACERT_get0_notAfter(const X509_ACERT *x)
{
    return x->acinfo->validityPeriod.notAfter;
}

/* Attribute management functions */

int X509_ACERT_get_attr_count(const X509_ACERT *x)
{
    return X509at_get_attr_count(x->acinfo->attributes);
}

int X509_ACERT_get_attr_by_NID(const X509_ACERT *x, int nid, int lastpos)
{
    return X509at_get_attr_by_NID(x->acinfo->attributes, nid, lastpos);
}

int X509_ACERT_get_attr_by_OBJ(const X509_ACERT *x, const ASN1_OBJECT *obj,
                               int lastpos)
{
    return X509at_get_attr_by_OBJ(x->acinfo->attributes, obj, lastpos);
}

X509_ATTRIBUTE *X509_ACERT_get_attr(const X509_ACERT *x, int loc)
{
    return X509at_get_attr(x->acinfo->attributes, loc);
}

X509_ATTRIBUTE *X509_ACERT_delete_attr(X509_ACERT *x, int loc)
{
    return X509at_delete_attr(x->acinfo->attributes, loc);
}

int X509_ACERT_add1_attr(X509_ACERT *x, X509_ATTRIBUTE *attr)
{
    if (X509at_add1_attr(&x->acinfo->attributes, attr))
        return 1;
    return 0;
}

ASN1_BIT_STRING *X509_ACERT_get0_issuerUID(X509_ACERT *x)
{
    return x->acinfo->issuerUID;
}

const STACK_OF(X509_EXTENSION) *X509_ACERT_get0_extensions(const X509_ACERT *x)
{
    return x->acinfo->extensions;
}
