/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int X509_ACERT_print_ex(BIO *bp, X509_ACERT *x, unsigned long nmflags,
                      unsigned long cflag)
{
    long l;
    int i;
    const STACK_OF(X509_EXTENSION) *exts;
    char mlch = ' ';

    if ((nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mlch = '\n';
    }

    if (!(cflag & X509_FLAG_NO_HEADER)) {
        if (BIO_printf(bp, "Attribute Certificate:\n") <= 0)
            goto err;
        if (BIO_write(bp, "    Data:\n", 10) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VERSION)) {
        l = X509_ACERT_get_version(x);
        if (l == X509_ACERT_VERSION_2) {
            if (BIO_printf(bp, "%8sVersion: %ld (0x%lx)\n", "", l + 1, (unsigned long)l) <= 0)
                goto err;
        } else {
            if (BIO_printf(bp, "%8sVersion: Unknown (%ld)\n", "", l) <= 0)
                goto err;
        }
    }
    if (!(cflag & X509_FLAG_NO_SUBJECT)) {
        const X509_NAME *holderEntities;
        X509_NAME *holderIssuer;
        ASN1_INTEGER *holder_serial;

        if (BIO_printf(bp, "        Holder:\n") <= 0)
            goto err;

        holderEntities = X509_ACERT_get0_holder_entityName(x);
        if (holderEntities) {
            if (BIO_printf(bp, "            Name:%c", mlch) <= 0)
                goto err;

            if (X509_NAME_print(bp, holderEntities, 0) <= 0)
                goto err;
        }

        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;

        X509_ACERT_get0_holder_baseCertId(&holderIssuer, &holder_serial, NULL, x);
        if (holderIssuer) {
            if (BIO_printf(bp, "            Issuer:%c", mlch) <= 0)
                goto err;

            if (X509_NAME_print(bp, holderIssuer, 0) <= 0)
                goto err;

            if (BIO_write(bp, "\n", 1) <= 0)
                goto err;

            if (BIO_printf(bp, "            Serial: ") <= 0)
                goto err;
    
            char *serial_str = BN_bn2hex(ASN1_INTEGER_to_BN(holder_serial, NULL));
            if (BIO_printf(bp, "%s", serial_str) <= 0) {
                OPENSSL_free (serial_str);
                goto err;
            }
            OPENSSL_free (serial_str);
        }

        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;

    }

    if (!(cflag & X509_FLAG_NO_ISSUER)) {
        if (BIO_printf(bp, "        Issuer:%c", mlch) <= 0)
            goto err;
        if (X509_NAME_print_ex(bp, X509_ACERT_get0_issuerName(x), 0, nmflags)
            < 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }
    if (!(cflag & X509_FLAG_NO_VALIDITY)) {
        if (BIO_write(bp, "        Validity\n", 17) <= 0)
            goto err;
        if (BIO_write(bp, "            Not Before: ", 24) <= 0)
            goto err;
        if (ASN1_GENERALIZEDTIME_print(bp, X509_ACERT_get0_notBefore(x)) == 0)
            goto err;
        if (BIO_write(bp, "\n            Not After : ", 25) <= 0)
            goto err;
        if (ASN1_GENERALIZEDTIME_print(bp, X509_ACERT_get0_notAfter(x)) == 0)
            goto err;
        if (BIO_write(bp, "\n", 1) <= 0)
            goto err;
    }

    if (!(cflag & X509_FLAG_NO_ATTRIBUTES)) {
        if (BIO_printf(bp, "%8sAttributes:\n", "") <= 0)
            goto err;

        if (X509_ACERT_get_attr_count(x) == 0) {
            if (BIO_printf(bp, "%12s(none)\n", "") <= 0)
                goto err;
        } else {
            for (i = 0; i < X509_ACERT_get_attr_count(x); i++) {
                ASN1_TYPE *at;
                X509_ATTRIBUTE *a;
                ASN1_BIT_STRING *bs = NULL;
                ASN1_OBJECT *aobj;
                int j, type = 0, count = 1, ii = 0;

                a = X509_ACERT_get_attr(x, i);
                aobj = X509_ATTRIBUTE_get0_object(a);
                if (BIO_printf(bp, "%12s", "") <= 0)
                    goto err;
                if ((j = i2a_ASN1_OBJECT(bp, aobj)) > 0) {
                    ii = 0;
                    count = X509_ATTRIBUTE_count(a);
                    if (count == 0) {
                      ERR_raise(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES);
                      return 0;
                    }
 get_next:
                    at = X509_ATTRIBUTE_get0_type(a, ii);
                    type = at->type;
                    bs = at->value.asn1_string;
                }
                for (j = 25 - j; j > 0; j--)
                    if (BIO_write(bp, " ", 1) != 1)
                        goto err;
                if (BIO_puts(bp, ":") <= 0)
                    goto err;

                switch (OBJ_obj2nid(aobj)) {
                case NID_id_aca_group:
                case NID_id_aca_chargingIdentity:
                {
                    const unsigned char *seq_data = at->value.sequence->data;
                    IETF_ATTR_SYNTAX *ietf_value;
                    ietf_value = d2i_IETF_ATTR_SYNTAX(NULL, &seq_data,
                            at->value.sequence->length);

                    if (IETF_ATTR_SYNTAX_print_ex(bp, ietf_value, 1) <= 0)
                        goto err;
                    continue;
                }
                default:
                    break;
                }
                switch (type) {
                case V_ASN1_PRINTABLESTRING:
                case V_ASN1_T61STRING:
                case V_ASN1_NUMERICSTRING:
                case V_ASN1_UTF8STRING:
                case V_ASN1_IA5STRING:
                    if (BIO_write(bp, (char *)bs->data, bs->length)
                            != bs->length)
                        goto err;
                    if (BIO_puts(bp, "\n") <= 0)
                        goto err;
                    break;
                default:
                    if (BIO_puts(bp, "unable to print attribute\n") <= 0)
                        goto err;
                    break;
                }
                if (++ii < count)
                    goto get_next;
            }
        }
    }
    if (!(cflag & X509_FLAG_NO_EXTENSIONS)) {
        exts = X509_ACERT_get0_extensions(x);
        if (exts) {
            if (BIO_printf(bp, "%8sExtensions:\n", "") <= 0)
                goto err;
            for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
                ASN1_OBJECT *obj;
                X509_EXTENSION *ex;
                int critical;
                ex = sk_X509_EXTENSION_value(exts, i);
                if (BIO_printf(bp, "%12s", "") <= 0)
                    goto err;
                obj = X509_EXTENSION_get_object(ex);
                if (i2a_ASN1_OBJECT(bp, obj) <= 0)
                    goto err;
                critical = X509_EXTENSION_get_critical(ex);
                if (BIO_printf(bp, ": %s\n", critical ? "critical" : "") <= 0)
                    goto err;
                if (!X509V3_EXT_print(bp, ex, cflag, 20)) {
                    if (BIO_printf(bp, "%16s", "") <= 0
                        || ASN1_STRING_print(bp,
                                             X509_EXTENSION_get_data(ex)) <= 0)
                        goto err;
                }
                if (BIO_write(bp, "\n", 1) <= 0)
                    goto err;
            }
        }
    }

    if (!(cflag & X509_FLAG_NO_SIGDUMP)) {
        const X509_ALGOR *sig_alg;
        const ASN1_BIT_STRING *sig;
        X509_ACERT_get0_signature(x, &sig, &sig_alg);
        if (!X509_signature_print(bp, sig_alg, sig))
            goto err;
    }

    return 1;
 err:
    ERR_raise(ERR_LIB_X509, ERR_R_BUF_LIB);
    return 0;
}

int X509_ACERT_print(BIO *bp, X509_ACERT *x)
{
    return X509_ACERT_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
}
