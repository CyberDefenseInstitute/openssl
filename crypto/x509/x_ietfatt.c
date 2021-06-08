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

ASN1_CHOICE(IETF_ATTR_SYNTAX_VALUE) = {
    ASN1_SIMPLE(IETF_ATTR_SYNTAX_VALUE, u.octets, ASN1_OCTET_STRING),
    ASN1_SIMPLE(IETF_ATTR_SYNTAX_VALUE, u.oid, ASN1_OBJECT),
    ASN1_SIMPLE(IETF_ATTR_SYNTAX_VALUE, u.string, ASN1_UTF8STRING),
} ASN1_CHOICE_END(IETF_ATTR_SYNTAX_VALUE)

ASN1_SEQUENCE(IETF_ATTR_SYNTAX) = {
    ASN1_IMP_SEQUENCE_OF_OPT(IETF_ATTR_SYNTAX, policyAuthority, GENERAL_NAME, 0),
    ASN1_SEQUENCE_OF(IETF_ATTR_SYNTAX, values, IETF_ATTR_SYNTAX_VALUE),
} ASN1_SEQUENCE_END(IETF_ATTR_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(IETF_ATTR_SYNTAX)

int IETF_ATTR_SYNTAX_get_values(const IETF_ATTR_SYNTAX *a)
{

    return sk_IETF_ATTR_SYNTAX_VALUE_num(a->values);
}

const GENERAL_NAMES *IETF_ATTR_SYNTAX_get0_policyAuthority(const IETF_ATTR_SYNTAX *a)
{
    return a->policyAuthority;
}

void *IETF_ATTR_SYNTAX_get0_value(const IETF_ATTR_SYNTAX *a, int ind, int *type)
{

    IETF_ATTR_SYNTAX_VALUE *val = sk_IETF_ATTR_SYNTAX_VALUE_value(a->values, ind);
    if (*type)
        *type = val->type;

    switch (val->type) {
    case IETFAS_OCTETS:
        return val->u.octets;
    case IETFAS_OID:
        return val->u.oid;
    case IETFAS_STRING:
        return val->u.string;
    }

    return NULL;
}


int IETF_ATTR_SYNTAX_print_ex(BIO *bp, IETF_ATTR_SYNTAX *a, int indent)
{
    if (a->policyAuthority) {
        for (int i = 0; i < sk_GENERAL_NAME_num(a->policyAuthority); i++) {
            if (BIO_printf(bp, "%*s", indent, "") <= 0)
                goto err;

            if (GENERAL_NAME_print(bp, sk_GENERAL_NAME_value(a->policyAuthority, i)) <= 0)
                goto err;

            if (BIO_printf(bp, "\n") <= 0)
                goto err;
        }
    }

    for (int i = 0; i < IETF_ATTR_SYNTAX_get_values(a); i++) {
        int ietf_type;
        void *attr_value = IETF_ATTR_SYNTAX_get0_value(a, i, &ietf_type);

        if (BIO_printf(bp, "%*s", indent, "") <= 0)
                goto err;

        switch(ietf_type) {
        case IETFAS_OCTETS:
            //TODO
            break;
        case IETFAS_OID:
            //TODO
            break;
        case IETFAS_STRING:
            {
            ASN1_UTF8STRING *str = attr_value;
            BIO_printf(bp, "%*s", str->length, str->data);
            break;
            }
        }
    }
    if (BIO_printf(bp, "\n") <= 0)
        goto err;

    return 1;

err:
    return 0;
}
