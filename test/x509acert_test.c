/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>

#include "internal/nelem.h"
#include "testutil.h"

char *acert_file = NULL;

static int test_read_acert(void)
{
    X509_ACERT *acert = NULL;
    BIO *bp = NULL, *bout = NULL;
    int ret = 0;
    if (!TEST_ptr(bp = BIO_new_file(acert_file, "r")))
        goto err;

    if (!TEST_ptr(acert = PEM_read_bio_X509_ACERT(bp, NULL, NULL, NULL)))
        goto err;

    if (!TEST_ptr(bout = BIO_new_fp(stdout, BIO_NOCLOSE)))
        goto err;

    if (!TEST_int_gt(X509_ACERT_print(bout, acert), 0))
        goto err;

    ret = 1;
err:
    BIO_free(bp);
    BIO_free(bout);
    X509_ACERT_free(acert);
    ERR_print_errors_fp(stdout);
    return ret;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(acert_file = test_get_argument(0)))
        return 0;


    ADD_TEST(test_read_acert);
    return 1;
}