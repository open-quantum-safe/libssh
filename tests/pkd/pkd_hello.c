/*
 * pkd_hello.c --
 *
 * (c) 2014, 2017-2018 Jon Simons <jon@jonsimons.org>
 */
#include "config.h"

#include <setjmp.h> // for cmocka
#include <stdarg.h> // for cmocka
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // for cmocka
#include <cmocka.h>

#include "libssh/priv.h"
#include "torture.h" // for ssh_fips_mode()

#include "pkd_client.h"
#include "pkd_daemon.h"
#include "pkd_keyutil.h"
#include "pkd_util.h"

#define DEFAULT_ITERATIONS 10
static struct pkd_daemon_args pkd_dargs;

static uint8_t default_payload_buf[] = {
    'h', 'e', 'l', 'l', 'o', '\n',
};

static size_t default_payload_len = sizeof(default_payload_buf);

#ifdef HAVE_ARGP_H
#include <argp.h>
#define PROGNAME "pkd_hello"
#define ARGP_PROGNAME "libssh " PROGNAME
const char *argp_program_version = ARGP_PROGNAME " 2017-07-12";
const char *argp_program_bug_address = "Jon Simons <jon@jonsimons.org>";

static char doc[] = \
    "\nExample usage:\n\n"
    "    " PROGNAME "\n"
    "        Run all tests with default number of iterations.\n"
    "    " PROGNAME " --list\n"
    "        List available individual test names.\n"
    "    " PROGNAME " -i 1000 -t torture_pkd_rsa_ecdh_sha2_nistp256\n"
    "        Run only the torture_pkd_rsa_ecdh_sha2_nistp256 testcase 1000 times.\n"
    "    " PROGNAME " -i 1000 -m curve25519\n"
    "        Run all tests with the string 'curve25519' 1000 times.\n"
    "    " PROGNAME " -v -v -v -v -e -o\n"
    "        Run all tests with maximum libssh and pkd logging.\n"
;

static struct argp_option options[] = {
    { "buffer", 'b', "string", 0,
      "Use the given string for test buffer payload contents", 0 },
    { "stderr", 'e', NULL, 0,
      "Emit pkd stderr messages", 0 },
    { "list", 'l', NULL, 0,
      "List available individual test names", 0 },
    { "iterations", 'i', "number", 0,
      "Run each test for the given number of iterations (default is 10)", 0 },
    { "match", 'm', "testmatch", 0,
      "Run all tests with the given string", 0 },
    { "socket-wrapper-dir", 'w', "<mkdtemp-template>", 0,
      "Run in socket-wrapper mode using the given mkdtemp directory template", 0 },
    { "stdout", 'o', NULL, 0,
      "Emit pkd stdout messages", 0 },
    { "preserve", 'p', NULL, 0,
      "Preserve client and server authentication keys (preserved keys will be re-used by a future run)", 0 },
    { "rekey", 'r', "limit", 0,
      "Set the given rekey data limit, in bytes, using SSH_OPTIONS_REKEY_DATA", 0 },
    { "test", 't', "testname", 0,
      "Run tests matching the given testname", 0 },
    { "verbose", 'v', NULL, 0,
      "Increase libssh verbosity (can be used multiple times)", 0 },
    { NULL, 0, NULL, 0,
      NULL, 0 },
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    (void) arg;
    (void) state;

    switch(key) {
    case 'b':
        pkd_dargs.payload.buf = (uint8_t *) arg;
        pkd_dargs.payload.len = strlen(arg);
        break;
    case 'e':
        pkd_dargs.opts.log_stderr = 1;
        break;
    case 'l':
        pkd_dargs.opts.list = 1;
        break;
    case 'i':
        pkd_dargs.opts.iterations = atoi(arg);
        break;
    case 'm':
        pkd_dargs.opts.testmatch = arg;
        break;
    case 'o':
        pkd_dargs.opts.log_stdout = 1;
        break;
    case 'p':
        pkd_dargs.opts.preserve_keys = 1;
        break;
    case 'r':
        pkd_dargs.rekey_data_limit = atoi(arg);
        break;
    case 't':
        pkd_dargs.opts.testname = arg;
        break;
    case 'v':
        pkd_dargs.opts.libssh_log_level += 1;
        break;
    case 'w':
        pkd_dargs.opts.socket_wrapper.mkdtemp_str = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp parser = {
    options,
    parse_opt,
    NULL,
    doc,
    NULL,
    NULL,
    NULL
};
#endif /* HAVE_ARGP_H */

static struct pkd_state *torture_pkd_setup(enum pkd_hostkey_type_e type,
                                           const char *hostkeypath) {
    int rc = 0;

    pkd_dargs.type = type;
    pkd_dargs.hostkeypath = hostkeypath;

    rc = pkd_start(&pkd_dargs);
    assert_int_equal(rc, 0);

    return NULL;
}

static int torture_pkd_teardown(void **state) {
    struct pkd_result result = { .ok = 0 };

    (void) state;

    pkd_stop(&result);
    assert_int_equal(result.ok, 1);

    return 0;
}

/*
 * one setup for each server keytype ------------------------------------
 */

static int torture_pkd_setup_noop(void **state) {
    *state = (void *) torture_pkd_setup(PKD_RSA, NULL /*path*/);

    return 0;
}

static int torture_pkd_setup_rsa(void **state) {
    setup_rsa_key();
    *state = (void *) torture_pkd_setup(PKD_RSA, LIBSSH_RSA_TESTKEY);

    return 0;
}

static int torture_pkd_setup_ed25519(void **state) {
    setup_ed25519_key();
    *state = (void *) torture_pkd_setup(PKD_ED25519, LIBSSH_ED25519_TESTKEY);

    return 0;
}

#ifdef HAVE_DSA
static int torture_pkd_setup_dsa(void **state) {
    setup_dsa_key();
    *state = (void *) torture_pkd_setup(PKD_DSA, LIBSSH_DSA_TESTKEY);

    return 0;
}
#endif

static int torture_pkd_setup_ecdsa_256(void **state) {
    setup_ecdsa_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA, LIBSSH_ECDSA_256_TESTKEY);

    return 0;
}

static int torture_pkd_setup_ecdsa_384(void **state) {
    setup_ecdsa_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA, LIBSSH_ECDSA_384_TESTKEY);

    return 0;
}

static int torture_pkd_setup_ecdsa_521(void **state) {
    setup_ecdsa_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA, LIBSSH_ECDSA_521_TESTKEY);

    return 0;
}

#ifdef WITH_POST_QUANTUM_CRYPTO
///// OQS_TEMPLATE_FRAGMENT_OQS_SETUP_FUNCS_START
static int torture_pkd_setup_falcon_512(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_FALCON_512, LIBSSH_FALCON_512_TESTKEY);

    return 0;
}
static int torture_pkd_setup_rsa3072_falcon_512(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_RSA3072_FALCON_512, LIBSSH_RSA3072_FALCON_512_TESTKEY);

    return 0;
}
static int torture_pkd_setup_ecdsa_nistp256_falcon_512(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA_NISTP256_FALCON_512, LIBSSH_ECDSA_NISTP256_FALCON_512_TESTKEY);

    return 0;
}
static int torture_pkd_setup_falcon_1024(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_FALCON_1024, LIBSSH_FALCON_1024_TESTKEY);

    return 0;
}
static int torture_pkd_setup_ecdsa_nistp521_falcon_1024(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA_NISTP521_FALCON_1024, LIBSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY);

    return 0;
}
static int torture_pkd_setup_dilithium_3(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_DILITHIUM_3, LIBSSH_DILITHIUM_3_TESTKEY);

    return 0;
}
static int torture_pkd_setup_ecdsa_nistp384_dilithium_3(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA_NISTP384_DILITHIUM_3, LIBSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY);

    return 0;
}
static int torture_pkd_setup_dilithium_2_aes(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_DILITHIUM_2_AES, LIBSSH_DILITHIUM_2_AES_TESTKEY);

    return 0;
}
static int torture_pkd_setup_rsa3072_dilithium_2_aes(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_RSA3072_DILITHIUM_2_AES, LIBSSH_RSA3072_DILITHIUM_2_AES_TESTKEY);

    return 0;
}
static int torture_pkd_setup_ecdsa_nistp256_dilithium_2_aes(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA_NISTP256_DILITHIUM_2_AES, LIBSSH_ECDSA_NISTP256_DILITHIUM_2_AES_TESTKEY);

    return 0;
}
static int torture_pkd_setup_dilithium_5_aes(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_DILITHIUM_5_AES, LIBSSH_DILITHIUM_5_AES_TESTKEY);

    return 0;
}
static int torture_pkd_setup_ecdsa_nistp521_dilithium_5_aes(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA_NISTP521_DILITHIUM_5_AES, LIBSSH_ECDSA_NISTP521_DILITHIUM_5_AES_TESTKEY);

    return 0;
}
static int torture_pkd_setup_picnic_l1_full(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_PICNIC_L1_FULL, LIBSSH_PICNIC_L1_FULL_TESTKEY);

    return 0;
}
static int torture_pkd_setup_rsa3072_picnic_l1_full(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_RSA3072_PICNIC_L1_FULL, LIBSSH_RSA3072_PICNIC_L1_FULL_TESTKEY);

    return 0;
}
static int torture_pkd_setup_ecdsa_nistp256_picnic_l1_full(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA_NISTP256_PICNIC_L1_FULL, LIBSSH_ECDSA_NISTP256_PICNIC_L1_FULL_TESTKEY);

    return 0;
}
static int torture_pkd_setup_picnic_l3_fs(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_PICNIC_L3_FS, LIBSSH_PICNIC_L3_FS_TESTKEY);

    return 0;
}
static int torture_pkd_setup_ecdsa_nistp384_picnic_l3_fs(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA_NISTP384_PICNIC_L3_FS, LIBSSH_ECDSA_NISTP384_PICNIC_L3_FS_TESTKEY);

    return 0;
}
static int torture_pkd_setup_sphincs_haraka_128f_simple(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_SPHINCS_HARAKA_128F_SIMPLE, LIBSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);

    return 0;
}
static int torture_pkd_setup_rsa3072_sphincs_haraka_128f_simple(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_RSA3072_SPHINCS_HARAKA_128F_SIMPLE, LIBSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);

    return 0;
}
static int torture_pkd_setup_ecdsa_nistp256_sphincs_haraka_128f_simple(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE, LIBSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY);

    return 0;
}
static int torture_pkd_setup_sphincs_haraka_192f_robust(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_SPHINCS_HARAKA_192F_ROBUST, LIBSSH_SPHINCS_HARAKA_192F_ROBUST_TESTKEY);

    return 0;
}
static int torture_pkd_setup_ecdsa_nistp384_sphincs_haraka_192f_robust(void** state) {
    setup_post_quantum_keys();
    *state = (void *) torture_pkd_setup(PKD_ECDSA_NISTP384_SPHINCS_HARAKA_192F_ROBUST, LIBSSH_ECDSA_NISTP384_SPHINCS_HARAKA_192F_ROBUST_TESTKEY);

    return 0;
}
///// OQS_TEMPLATE_FRAGMENT_OQS_SETUP_FUNCS_END
#endif
/*
 * Test matrices: f(clientname, testname, ssh-command, setup-function, teardown-function).
 */

#define PKDTESTS_DEFAULT_FIPS(f, client, cmd) \
    f(client, rsa_default,        cmd,  setup_rsa,        teardown) \
    f(client, ecdsa_256_default,  cmd,  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_default,  cmd,  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_default,  cmd,  setup_ecdsa_521,  teardown)

#ifdef HAVE_DSA
#define PKDTESTS_DEFAULT(f, client, cmd) \
    /* Default passes by server key type. */ \
    PKDTESTS_DEFAULT_FIPS(f, client, cmd) \
    f(client, dsa_default,        cmd,  setup_dsa,        teardown)
#else
#define PKDTESTS_DEFAULT(f, client, cmd) \
    /* Default passes by server key type. */ \
    PKDTESTS_DEFAULT_FIPS(f, client, cmd)
#endif

#define PKDTESTS_DEFAULT_OPENSSHONLY(f, client, cmd) \
    /* Default passes by server key type. */ \
    f(client, ed25519_default,    cmd,  setup_ed25519,    teardown)

#define GEX_SHA256 "diffie-hellman-group-exchange-sha256"
#define GEX_SHA1   "diffie-hellman-group-exchange-sha1"

#if defined(WITH_GEX)
#define PKDTESTS_KEX_FIPS(f, client, kexcmd) \
    f(client, rsa_ecdh_sha2_nistp256,                 kexcmd("ecdh-sha2-nistp256"),            setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp384,                 kexcmd("ecdh-sha2-nistp384"),            setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp521,                 kexcmd("ecdh-sha2-nistp521"),            setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group16_sha512,      kexcmd("diffie-hellman-group16-sha512"), setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group18_sha512,      kexcmd("diffie-hellman-group18-sha512"), setup_rsa,        teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_521,  teardown) \
    f(client, rsa_diffie_hellman_group_exchange_sha256,       kexcmd(GEX_SHA256),              setup_rsa,        teardown) \
    f(client, ecdsa_256_diffie_hellman_group_exchange_sha256, kexcmd(GEX_SHA256),              setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group_exchange_sha256, kexcmd(GEX_SHA256),              setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group_exchange_sha256, kexcmd(GEX_SHA256),              setup_ecdsa_521,  teardown)
#else /* !defined(WITH_GEX) */
#define PKDTESTS_KEX_FIPS(f, client, kexcmd) \
    f(client, rsa_ecdh_sha2_nistp256,                 kexcmd("ecdh-sha2-nistp256"),            setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp384,                 kexcmd("ecdh-sha2-nistp384"),            setup_rsa,        teardown) \
    f(client, rsa_ecdh_sha2_nistp521,                 kexcmd("ecdh-sha2-nistp521"),            setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group14_sha256,      kexcmd("diffie-hellman-group14-sha256"), setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group16_sha512,      kexcmd("diffie-hellman-group16-sha512"), setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group18_sha512,      kexcmd("diffie-hellman-group18-sha512"), setup_rsa,        teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group14_sha256,kexcmd("diffie-hellman-group14-sha256"), setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group14_sha256,kexcmd("diffie-hellman-group14-sha256"), setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp256,           kexcmd("ecdh-sha2-nistp256"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp384,           kexcmd("ecdh-sha2-nistp384"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_ecdh_sha2_nistp521,           kexcmd("ecdh-sha2-nistp521"),            setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group14_sha256,kexcmd("diffie-hellman-group14-sha256"), setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group16_sha512,kexcmd("diffie-hellman-group16-sha512"), setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group18_sha512,kexcmd("diffie-hellman-group18-sha512"), setup_ecdsa_521,  teardown)
#endif

#define PKDTESTS_KEX_COMMON(f, client, kexcmd) \
    PKDTESTS_KEX_FIPS(f, client, kexcmd) \
    f(client, rsa_curve25519_sha256,                  kexcmd("curve25519-sha256"),             setup_rsa,        teardown) \
    f(client, rsa_curve25519_sha256_libssh_org,       kexcmd("curve25519-sha256@libssh.org"),  setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group14_sha1,        kexcmd("diffie-hellman-group14-sha1"),   setup_rsa,        teardown) \
    f(client, rsa_diffie_hellman_group1_sha1,         kexcmd("diffie-hellman-group1-sha1"),    setup_rsa,        teardown) \
    f(client, ecdsa_256_curve25519_sha256,            kexcmd("curve25519-sha256"),             setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_curve25519_sha256_libssh_org, kexcmd("curve25519-sha256@libssh.org"),  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group14_sha1,  kexcmd("diffie-hellman-group14-sha1"),   setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_diffie_hellman_group1_sha1,   kexcmd("diffie-hellman-group1-sha1"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_curve25519_sha256,            kexcmd("curve25519-sha256"),             setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_curve25519_sha256_libssh_org, kexcmd("curve25519-sha256@libssh.org"),  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group14_sha1,  kexcmd("diffie-hellman-group14-sha1"),   setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group1_sha1,   kexcmd("diffie-hellman-group1-sha1"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_curve25519_sha256,            kexcmd("curve25519-sha256"),             setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_curve25519_sha256_libssh_org, kexcmd("curve25519-sha256@libssh.org"),  setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group14_sha1,  kexcmd("diffie-hellman-group14-sha1"),   setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group1_sha1,   kexcmd("diffie-hellman-group1-sha1"),    setup_ecdsa_521,  teardown)

#if defined(HAVE_DSA) && defined(WITH_GEX)
    /* GEX_SHA256 with RSA and ECDSA is included in PKDTESTS_KEX_FIPS if available */
#define PKDTESTS_KEX(f, client, kexcmd) \
    /* Kex algorithms. */ \
    PKDTESTS_KEX_COMMON(f, client, kexcmd) \
    f(client, rsa_diffie_hellman_group_exchange_sha1, kexcmd(GEX_SHA1),                        setup_rsa,        teardown) \
    f(client, dsa_curve25519_sha256,                  kexcmd("curve25519-sha256"),             setup_dsa,        teardown) \
    f(client, dsa_curve25519_sha256_libssh_org,       kexcmd("curve25519-sha256@libssh.org"),  setup_dsa,        teardown) \
    f(client, dsa_ecdh_sha2_nistp256,                 kexcmd("ecdh-sha2-nistp256 "),           setup_dsa,        teardown) \
    f(client, dsa_ecdh_sha2_nistp384,                 kexcmd("ecdh-sha2-nistp384 "),           setup_dsa,        teardown) \
    f(client, dsa_ecdh_sha2_nistp521,                 kexcmd("ecdh-sha2-nistp521 "),           setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group16_sha512,      kexcmd("diffie-hellman-group16-sha512"), setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group18_sha512,      kexcmd("diffie-hellman-group18-sha512"), setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group14_sha1,        kexcmd("diffie-hellman-group14-sha1"),   setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group14_sha256,      kexcmd("diffie-hellman-group14-sha256"), setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group1_sha1,         kexcmd("diffie-hellman-group1-sha1"),    setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group_exchange_sha256, kexcmd(GEX_SHA256),                    setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group_exchange_sha1, kexcmd(GEX_SHA1),                        setup_dsa,        teardown) \
    f(client, ecdsa_256_diffie_hellman_group_exchange_sha1, kexcmd(GEX_SHA1),                  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group_exchange_sha1, kexcmd(GEX_SHA1),                  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group_exchange_sha1, kexcmd(GEX_SHA1),                  setup_ecdsa_521,  teardown)

#elif defined(HAVE_DSA) /* && !defined(WITH_GEX) */
#define PKDTESTS_KEX(f, client, kexcmd) \
    /* Kex algorithms. */ \
    PKDTESTS_KEX_COMMON(f, client, kexcmd) \
    f(client, dsa_curve25519_sha256,                  kexcmd("curve25519-sha256"),             setup_dsa,        teardown) \
    f(client, dsa_curve25519_sha256_libssh_org,       kexcmd("curve25519-sha256@libssh.org"),  setup_dsa,        teardown) \
    f(client, dsa_ecdh_sha2_nistp256,                 kexcmd("ecdh-sha2-nistp256 "),           setup_dsa,        teardown) \
    f(client, dsa_ecdh_sha2_nistp384,                 kexcmd("ecdh-sha2-nistp384 "),           setup_dsa,        teardown) \
    f(client, dsa_ecdh_sha2_nistp521,                 kexcmd("ecdh-sha2-nistp521 "),           setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group16_sha512,      kexcmd("diffie-hellman-group16-sha512"), setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group18_sha512,      kexcmd("diffie-hellman-group18-sha512"), setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group14_sha1,        kexcmd("diffie-hellman-group14-sha1"),   setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group14_sha256,      kexcmd("diffie-hellman-group14-sha256"), setup_dsa,        teardown) \
    f(client, dsa_diffie_hellman_group1_sha1,         kexcmd("diffie-hellman-group1-sha1"),    setup_dsa,        teardown)

#elif defined(WITH_GEX) /* && !defined(HAVE_DSA) */
    /* GEX_SHA256 is included in PKDTESTS_KEX_FIPS if available */
#define PKDTESTS_KEX(f, client, kexcmd) \
    /* Kex algorithms. */ \
    PKDTESTS_KEX_COMMON(f, client, kexcmd) \
    f(client, rsa_diffie_hellman_group_exchange_sha1,         kexcmd(GEX_SHA1),                setup_rsa,        teardown) \
    f(client, ecdsa_256_diffie_hellman_group_exchange_sha1,   kexcmd(GEX_SHA1),                setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_diffie_hellman_group_exchange_sha1,   kexcmd(GEX_SHA1),                setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_diffie_hellman_group_exchange_sha1,   kexcmd(GEX_SHA1),                setup_ecdsa_521,  teardown)
#else
#define PKDTESTS_KEX(f, client, kexcmd) \
    /* Kex algorithms. */ \
    PKDTESTS_KEX_COMMON(f, client, kexcmd)
#endif

#ifdef HAVE_DSA
#define PKDTESTS_KEX_OPENSSHONLY(f, client, kexcmd) \
    /* Kex algorithms. */ \
    f(client, ed25519_curve25519_sha256,              kexcmd("curve25519-sha256"),             setup_ed25519,    teardown) \
    f(client, ed25519_curve25519_sha256_libssh_org,   kexcmd("curve25519-sha256@libssh.org"),  setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp256,             kexcmd("ecdh-sha2-nistp256"),            setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp384,             kexcmd("ecdh-sha2-nistp384"),            setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp521,             kexcmd("ecdh-sha2-nistp521"),            setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group14_sha256,  kexcmd("diffie-hellman-group14-sha256"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group16_sha512,  kexcmd("diffie-hellman-group16-sha512"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group18_sha512,  kexcmd("diffie-hellman-group18-sha512"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group14_sha1,    kexcmd("diffie-hellman-group14-sha1"),   setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group1_sha1,     kexcmd("diffie-hellman-group1-sha1"),    setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group_exchange_sha256, kexcmd(GEX_SHA256),                setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group_exchange_sha1, kexcmd(GEX_SHA1),                    setup_ed25519,    teardown)
#else
#define PKDTESTS_KEX_OPENSSHONLY(f, client, kexcmd) \
    /* Kex algorithms. */ \
    f(client, ed25519_curve25519_sha256,              kexcmd("curve25519-sha256"),             setup_ed25519,    teardown) \
    f(client, ed25519_curve25519_sha256_libssh_org,   kexcmd("curve25519-sha256@libssh.org"),  setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp256,             kexcmd("ecdh-sha2-nistp256"),            setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp384,             kexcmd("ecdh-sha2-nistp384"),            setup_ed25519,    teardown) \
    f(client, ed25519_ecdh_sha2_nistp521,             kexcmd("ecdh-sha2-nistp521"),            setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group14_sha256,  kexcmd("diffie-hellman-group14-sha256"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group16_sha512,  kexcmd("diffie-hellman-group16-sha512"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group18_sha512,  kexcmd("diffie-hellman-group18-sha512"), setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group1_sha1,     kexcmd("diffie-hellman-group1-sha1"),    setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group_exchange_sha256, kexcmd(GEX_SHA256),                setup_ed25519,    teardown) \
    f(client, ed25519_diffie_hellman_group_exchange_sha1, kexcmd(GEX_SHA1),                    setup_ed25519,    teardown)
#endif

#ifdef WITH_POST_QUANTUM_CRYPTO
///// OQS_TEMPLATE_FRAGMENT_KEX_TEST_CASES_START
#define PKDTESTS_KEX_OQS_PUREPQ(f, client, kexcmd) \
    f(client, rsa_frodokem_640_aes_sha256, kexcmd(KEX_FRODOKEM_640_AES_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_frodokem_640_aes_sha256, kexcmd(KEX_FRODOKEM_640_AES_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_frodokem_640_aes_sha256, kexcmd(KEX_FRODOKEM_640_AES_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_frodokem_976_aes_sha384, kexcmd(KEX_FRODOKEM_976_AES_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_frodokem_976_aes_sha384, kexcmd(KEX_FRODOKEM_976_AES_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_frodokem_976_aes_sha384, kexcmd(KEX_FRODOKEM_976_AES_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_frodokem_1344_aes_sha512, kexcmd(KEX_FRODOKEM_1344_AES_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_frodokem_1344_aes_sha512, kexcmd(KEX_FRODOKEM_1344_AES_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_frodokem_1344_aes_sha512, kexcmd(KEX_FRODOKEM_1344_AES_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_frodokem_640_shake_sha256, kexcmd(KEX_FRODOKEM_640_SHAKE_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_frodokem_640_shake_sha256, kexcmd(KEX_FRODOKEM_640_SHAKE_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_frodokem_640_shake_sha256, kexcmd(KEX_FRODOKEM_640_SHAKE_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_frodokem_976_shake_sha384, kexcmd(KEX_FRODOKEM_976_SHAKE_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_frodokem_976_shake_sha384, kexcmd(KEX_FRODOKEM_976_SHAKE_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_frodokem_976_shake_sha384, kexcmd(KEX_FRODOKEM_976_SHAKE_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_frodokem_1344_shake_sha512, kexcmd(KEX_FRODOKEM_1344_SHAKE_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_frodokem_1344_shake_sha512, kexcmd(KEX_FRODOKEM_1344_SHAKE_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_frodokem_1344_shake_sha512, kexcmd(KEX_FRODOKEM_1344_SHAKE_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_sidh_p434_sha256, kexcmd(KEX_SIDH_P434_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sidh_p434_sha256, kexcmd(KEX_SIDH_P434_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sidh_p434_sha256, kexcmd(KEX_SIDH_P434_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sidh_p434_compressed_sha256, kexcmd(KEX_SIDH_P434_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sidh_p434_compressed_sha256, kexcmd(KEX_SIDH_P434_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sidh_p434_compressed_sha256, kexcmd(KEX_SIDH_P434_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sidh_p610_sha256, kexcmd(KEX_SIDH_P610_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sidh_p610_sha256, kexcmd(KEX_SIDH_P610_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sidh_p610_sha256, kexcmd(KEX_SIDH_P610_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sidh_p610_compressed_sha256, kexcmd(KEX_SIDH_P610_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sidh_p610_compressed_sha256, kexcmd(KEX_SIDH_P610_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sidh_p610_compressed_sha256, kexcmd(KEX_SIDH_P610_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sidh_p751_sha256, kexcmd(KEX_SIDH_P751_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sidh_p751_sha256, kexcmd(KEX_SIDH_P751_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sidh_p751_sha256, kexcmd(KEX_SIDH_P751_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sidh_p751_compressed_sha256, kexcmd(KEX_SIDH_P751_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sidh_p751_compressed_sha256, kexcmd(KEX_SIDH_P751_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sidh_p751_compressed_sha256, kexcmd(KEX_SIDH_P751_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sike_p434_sha256, kexcmd(KEX_SIKE_P434_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sike_p434_sha256, kexcmd(KEX_SIKE_P434_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sike_p434_sha256, kexcmd(KEX_SIKE_P434_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sike_p434_compressed_sha256, kexcmd(KEX_SIKE_P434_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sike_p434_compressed_sha256, kexcmd(KEX_SIKE_P434_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sike_p434_compressed_sha256, kexcmd(KEX_SIKE_P434_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sike_p610_sha256, kexcmd(KEX_SIKE_P610_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sike_p610_sha256, kexcmd(KEX_SIKE_P610_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sike_p610_sha256, kexcmd(KEX_SIKE_P610_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sike_p610_compressed_sha256, kexcmd(KEX_SIKE_P610_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sike_p610_compressed_sha256, kexcmd(KEX_SIKE_P610_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sike_p610_compressed_sha256, kexcmd(KEX_SIKE_P610_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sike_p751_sha256, kexcmd(KEX_SIKE_P751_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sike_p751_sha256, kexcmd(KEX_SIKE_P751_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sike_p751_sha256, kexcmd(KEX_SIKE_P751_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_sike_p751_compressed_sha256, kexcmd(KEX_SIKE_P751_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_sike_p751_compressed_sha256, kexcmd(KEX_SIKE_P751_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_sike_p751_compressed_sha256, kexcmd(KEX_SIKE_P751_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_saber_lightsaber_sha256, kexcmd(KEX_SABER_LIGHTSABER_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_saber_lightsaber_sha256, kexcmd(KEX_SABER_LIGHTSABER_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_saber_lightsaber_sha256, kexcmd(KEX_SABER_LIGHTSABER_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_saber_saber_sha384, kexcmd(KEX_SABER_SABER_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_saber_saber_sha384, kexcmd(KEX_SABER_SABER_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_saber_saber_sha384, kexcmd(KEX_SABER_SABER_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_saber_firesaber_sha512, kexcmd(KEX_SABER_FIRESABER_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_saber_firesaber_sha512, kexcmd(KEX_SABER_FIRESABER_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_saber_firesaber_sha512, kexcmd(KEX_SABER_FIRESABER_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_kyber_512_sha256, kexcmd(KEX_KYBER_512_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_kyber_512_sha256, kexcmd(KEX_KYBER_512_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_kyber_512_sha256, kexcmd(KEX_KYBER_512_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_kyber_768_sha384, kexcmd(KEX_KYBER_768_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_kyber_768_sha384, kexcmd(KEX_KYBER_768_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_kyber_768_sha384, kexcmd(KEX_KYBER_768_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_kyber_1024_sha512, kexcmd(KEX_KYBER_1024_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_kyber_1024_sha512, kexcmd(KEX_KYBER_1024_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_kyber_1024_sha512, kexcmd(KEX_KYBER_1024_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_kyber_512_90s_sha256, kexcmd(KEX_KYBER_512_90S_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_kyber_512_90s_sha256, kexcmd(KEX_KYBER_512_90S_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_kyber_512_90s_sha256, kexcmd(KEX_KYBER_512_90S_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_kyber_768_90s_sha384, kexcmd(KEX_KYBER_768_90S_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_kyber_768_90s_sha384, kexcmd(KEX_KYBER_768_90S_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_kyber_768_90s_sha384, kexcmd(KEX_KYBER_768_90S_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_kyber_1024_90s_sha512, kexcmd(KEX_KYBER_1024_90S_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_kyber_1024_90s_sha512, kexcmd(KEX_KYBER_1024_90S_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_kyber_1024_90s_sha512, kexcmd(KEX_KYBER_1024_90S_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_bike_l1_sha512, kexcmd(KEX_BIKE_L1_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_bike_l1_sha512, kexcmd(KEX_BIKE_L1_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_bike_l1_sha512, kexcmd(KEX_BIKE_L1_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_bike_l3_sha512, kexcmd(KEX_BIKE_L3_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_bike_l3_sha512, kexcmd(KEX_BIKE_L3_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_bike_l3_sha512, kexcmd(KEX_BIKE_L3_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntru_hps2048509_sha512, kexcmd(KEX_NTRU_HPS2048509_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ntru_hps2048509_sha512, kexcmd(KEX_NTRU_HPS2048509_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntru_hps2048509_sha512, kexcmd(KEX_NTRU_HPS2048509_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntru_hps2048677_sha512, kexcmd(KEX_NTRU_HPS2048677_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ntru_hps2048677_sha512, kexcmd(KEX_NTRU_HPS2048677_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntru_hps2048677_sha512, kexcmd(KEX_NTRU_HPS2048677_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntru_hps4096821_sha512, kexcmd(KEX_NTRU_HPS4096821_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ntru_hps4096821_sha512, kexcmd(KEX_NTRU_HPS4096821_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntru_hps4096821_sha512, kexcmd(KEX_NTRU_HPS4096821_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntru_hps40961229_sha512, kexcmd(KEX_NTRU_HPS40961229_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ntru_hps40961229_sha512, kexcmd(KEX_NTRU_HPS40961229_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntru_hps40961229_sha512, kexcmd(KEX_NTRU_HPS40961229_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntru_hrss701_sha512, kexcmd(KEX_NTRU_HRSS701_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ntru_hrss701_sha512, kexcmd(KEX_NTRU_HRSS701_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntru_hrss701_sha512, kexcmd(KEX_NTRU_HRSS701_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntru_hrss1373_sha512, kexcmd(KEX_NTRU_HRSS1373_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ntru_hrss1373_sha512, kexcmd(KEX_NTRU_HRSS1373_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntru_hrss1373_sha512, kexcmd(KEX_NTRU_HRSS1373_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_348864_sha256, kexcmd(KEX_CLASSIC_MCELIECE_348864_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_348864_sha256, kexcmd(KEX_CLASSIC_MCELIECE_348864_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_348864_sha256, kexcmd(KEX_CLASSIC_MCELIECE_348864_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_348864f_sha256, kexcmd(KEX_CLASSIC_MCELIECE_348864F_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_348864f_sha256, kexcmd(KEX_CLASSIC_MCELIECE_348864F_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_348864f_sha256, kexcmd(KEX_CLASSIC_MCELIECE_348864F_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_460896_sha512, kexcmd(KEX_CLASSIC_MCELIECE_460896_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_460896_sha512, kexcmd(KEX_CLASSIC_MCELIECE_460896_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_460896_sha512, kexcmd(KEX_CLASSIC_MCELIECE_460896_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_460896f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_460896F_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_460896f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_460896F_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_460896f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_460896F_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_6688128_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6688128_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_6688128_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6688128_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_6688128_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6688128_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_6688128f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6688128F_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_6688128f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6688128F_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_6688128f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6688128F_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_6960119_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6960119_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_6960119_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6960119_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_6960119_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6960119_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_6960119f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6960119F_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_6960119f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6960119F_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_6960119f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_6960119F_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_8192128_sha512, kexcmd(KEX_CLASSIC_MCELIECE_8192128_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_8192128_sha512, kexcmd(KEX_CLASSIC_MCELIECE_8192128_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_8192128_sha512, kexcmd(KEX_CLASSIC_MCELIECE_8192128_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_classic_mceliece_8192128f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_8192128F_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_classic_mceliece_8192128f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_8192128F_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_classic_mceliece_8192128f_sha512, kexcmd(KEX_CLASSIC_MCELIECE_8192128F_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_hqc_128_sha256, kexcmd(KEX_HQC_128_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_hqc_128_sha256, kexcmd(KEX_HQC_128_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_hqc_128_sha256, kexcmd(KEX_HQC_128_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_hqc_192_sha384, kexcmd(KEX_HQC_192_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_hqc_192_sha384, kexcmd(KEX_HQC_192_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_hqc_192_sha384, kexcmd(KEX_HQC_192_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_hqc_256_sha512, kexcmd(KEX_HQC_256_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_hqc_256_sha512, kexcmd(KEX_HQC_256_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_hqc_256_sha512, kexcmd(KEX_HQC_256_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntruprime_ntrulpr653_sha256, kexcmd(KEX_NTRUPRIME_NTRULPR653_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ntruprime_ntrulpr653_sha256, kexcmd(KEX_NTRUPRIME_NTRULPR653_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntruprime_ntrulpr653_sha256, kexcmd(KEX_NTRUPRIME_NTRULPR653_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntruprime_sntrup653_sha256, kexcmd(KEX_NTRUPRIME_SNTRUP653_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ntruprime_sntrup653_sha256, kexcmd(KEX_NTRUPRIME_SNTRUP653_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntruprime_sntrup653_sha256, kexcmd(KEX_NTRUPRIME_SNTRUP653_SHA256), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntruprime_ntrulpr761_sha384, kexcmd(KEX_NTRUPRIME_NTRULPR761_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ntruprime_ntrulpr761_sha384, kexcmd(KEX_NTRUPRIME_NTRULPR761_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntruprime_ntrulpr761_sha384, kexcmd(KEX_NTRUPRIME_NTRULPR761_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntruprime_sntrup761_sha384, kexcmd(KEX_NTRUPRIME_SNTRUP761_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ntruprime_sntrup761_sha384, kexcmd(KEX_NTRUPRIME_SNTRUP761_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntruprime_sntrup761_sha384, kexcmd(KEX_NTRUPRIME_SNTRUP761_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntruprime_ntrulpr857_sha384, kexcmd(KEX_NTRUPRIME_NTRULPR857_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ntruprime_ntrulpr857_sha384, kexcmd(KEX_NTRUPRIME_NTRULPR857_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntruprime_ntrulpr857_sha384, kexcmd(KEX_NTRUPRIME_NTRULPR857_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntruprime_sntrup857_sha384, kexcmd(KEX_NTRUPRIME_SNTRUP857_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ntruprime_sntrup857_sha384, kexcmd(KEX_NTRUPRIME_SNTRUP857_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntruprime_sntrup857_sha384, kexcmd(KEX_NTRUPRIME_SNTRUP857_SHA384), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntruprime_ntrulpr1277_sha512, kexcmd(KEX_NTRUPRIME_NTRULPR1277_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ntruprime_ntrulpr1277_sha512, kexcmd(KEX_NTRUPRIME_NTRULPR1277_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntruprime_ntrulpr1277_sha512, kexcmd(KEX_NTRUPRIME_NTRULPR1277_SHA512), setup_picnic_l1_full, teardown) \
    f(client, rsa_ntruprime_sntrup1277_sha512, kexcmd(KEX_NTRUPRIME_SNTRUP1277_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ntruprime_sntrup1277_sha512, kexcmd(KEX_NTRUPRIME_SNTRUP1277_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ntruprime_sntrup1277_sha512, kexcmd(KEX_NTRUPRIME_SNTRUP1277_SHA512), setup_picnic_l1_full, teardown)

#define PKDTESTS_KEX_OQS_HYBRID(f, client, kexcmd) \
    f(client, rsa_ecdh_nistp256_frodokem_640_aes_sha256, kexcmd(KEX_ECDH_NISTP256_FRODOKEM_640_AES_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_frodokem_640_aes_sha256, kexcmd(KEX_ECDH_NISTP256_FRODOKEM_640_AES_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_frodokem_640_aes_sha256, kexcmd(KEX_ECDH_NISTP256_FRODOKEM_640_AES_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_frodokem_640_aes_sha256, kexcmd(KEX_ECDH_NISTP256_FRODOKEM_640_AES_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_frodokem_976_aes_sha384, kexcmd(KEX_ECDH_NISTP384_FRODOKEM_976_AES_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_frodokem_976_aes_sha384, kexcmd(KEX_ECDH_NISTP384_FRODOKEM_976_AES_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_frodokem_976_aes_sha384, kexcmd(KEX_ECDH_NISTP384_FRODOKEM_976_AES_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_frodokem_976_aes_sha384, kexcmd(KEX_ECDH_NISTP384_FRODOKEM_976_AES_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_frodokem_1344_aes_sha512, kexcmd(KEX_ECDH_NISTP521_FRODOKEM_1344_AES_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_frodokem_1344_aes_sha512, kexcmd(KEX_ECDH_NISTP521_FRODOKEM_1344_AES_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_frodokem_1344_aes_sha512, kexcmd(KEX_ECDH_NISTP521_FRODOKEM_1344_AES_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_frodokem_1344_aes_sha512, kexcmd(KEX_ECDH_NISTP521_FRODOKEM_1344_AES_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_frodokem_640_shake_sha256, kexcmd(KEX_ECDH_NISTP256_FRODOKEM_640_SHAKE_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_frodokem_640_shake_sha256, kexcmd(KEX_ECDH_NISTP256_FRODOKEM_640_SHAKE_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_frodokem_640_shake_sha256, kexcmd(KEX_ECDH_NISTP256_FRODOKEM_640_SHAKE_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_frodokem_640_shake_sha256, kexcmd(KEX_ECDH_NISTP256_FRODOKEM_640_SHAKE_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_frodokem_976_shake_sha384, kexcmd(KEX_ECDH_NISTP384_FRODOKEM_976_SHAKE_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_frodokem_976_shake_sha384, kexcmd(KEX_ECDH_NISTP384_FRODOKEM_976_SHAKE_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_frodokem_976_shake_sha384, kexcmd(KEX_ECDH_NISTP384_FRODOKEM_976_SHAKE_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_frodokem_976_shake_sha384, kexcmd(KEX_ECDH_NISTP384_FRODOKEM_976_SHAKE_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_frodokem_1344_shake_sha512, kexcmd(KEX_ECDH_NISTP521_FRODOKEM_1344_SHAKE_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_frodokem_1344_shake_sha512, kexcmd(KEX_ECDH_NISTP521_FRODOKEM_1344_SHAKE_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_frodokem_1344_shake_sha512, kexcmd(KEX_ECDH_NISTP521_FRODOKEM_1344_SHAKE_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_frodokem_1344_shake_sha512, kexcmd(KEX_ECDH_NISTP521_FRODOKEM_1344_SHAKE_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_sidh_p434_sha256, kexcmd(KEX_ECDH_NISTP256_SIDH_P434_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_sidh_p434_sha256, kexcmd(KEX_ECDH_NISTP256_SIDH_P434_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_sidh_p434_sha256, kexcmd(KEX_ECDH_NISTP256_SIDH_P434_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_sidh_p434_sha256, kexcmd(KEX_ECDH_NISTP256_SIDH_P434_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_sidh_p434_compressed_sha256, kexcmd(KEX_ECDH_NISTP256_SIDH_P434_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_sidh_p434_compressed_sha256, kexcmd(KEX_ECDH_NISTP256_SIDH_P434_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_sidh_p434_compressed_sha256, kexcmd(KEX_ECDH_NISTP256_SIDH_P434_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_sidh_p434_compressed_sha256, kexcmd(KEX_ECDH_NISTP256_SIDH_P434_COMPRESSED_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_sidh_p610_sha256, kexcmd(KEX_ECDH_NISTP384_SIDH_P610_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_sidh_p610_sha256, kexcmd(KEX_ECDH_NISTP384_SIDH_P610_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_sidh_p610_sha256, kexcmd(KEX_ECDH_NISTP384_SIDH_P610_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_sidh_p610_sha256, kexcmd(KEX_ECDH_NISTP384_SIDH_P610_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_sidh_p610_compressed_sha256, kexcmd(KEX_ECDH_NISTP384_SIDH_P610_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_sidh_p610_compressed_sha256, kexcmd(KEX_ECDH_NISTP384_SIDH_P610_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_sidh_p610_compressed_sha256, kexcmd(KEX_ECDH_NISTP384_SIDH_P610_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_sidh_p610_compressed_sha256, kexcmd(KEX_ECDH_NISTP384_SIDH_P610_COMPRESSED_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_sidh_p751_sha256, kexcmd(KEX_ECDH_NISTP521_SIDH_P751_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_sidh_p751_sha256, kexcmd(KEX_ECDH_NISTP521_SIDH_P751_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_sidh_p751_sha256, kexcmd(KEX_ECDH_NISTP521_SIDH_P751_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_sidh_p751_sha256, kexcmd(KEX_ECDH_NISTP521_SIDH_P751_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_sidh_p751_compressed_sha256, kexcmd(KEX_ECDH_NISTP521_SIDH_P751_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_sidh_p751_compressed_sha256, kexcmd(KEX_ECDH_NISTP521_SIDH_P751_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_sidh_p751_compressed_sha256, kexcmd(KEX_ECDH_NISTP521_SIDH_P751_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_sidh_p751_compressed_sha256, kexcmd(KEX_ECDH_NISTP521_SIDH_P751_COMPRESSED_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_sike_p434_sha256, kexcmd(KEX_ECDH_NISTP256_SIKE_P434_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_sike_p434_sha256, kexcmd(KEX_ECDH_NISTP256_SIKE_P434_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_sike_p434_sha256, kexcmd(KEX_ECDH_NISTP256_SIKE_P434_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_sike_p434_sha256, kexcmd(KEX_ECDH_NISTP256_SIKE_P434_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_sike_p434_compressed_sha256, kexcmd(KEX_ECDH_NISTP256_SIKE_P434_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_sike_p434_compressed_sha256, kexcmd(KEX_ECDH_NISTP256_SIKE_P434_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_sike_p434_compressed_sha256, kexcmd(KEX_ECDH_NISTP256_SIKE_P434_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_sike_p434_compressed_sha256, kexcmd(KEX_ECDH_NISTP256_SIKE_P434_COMPRESSED_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_sike_p610_sha256, kexcmd(KEX_ECDH_NISTP384_SIKE_P610_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_sike_p610_sha256, kexcmd(KEX_ECDH_NISTP384_SIKE_P610_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_sike_p610_sha256, kexcmd(KEX_ECDH_NISTP384_SIKE_P610_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_sike_p610_sha256, kexcmd(KEX_ECDH_NISTP384_SIKE_P610_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_sike_p610_compressed_sha256, kexcmd(KEX_ECDH_NISTP384_SIKE_P610_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_sike_p610_compressed_sha256, kexcmd(KEX_ECDH_NISTP384_SIKE_P610_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_sike_p610_compressed_sha256, kexcmd(KEX_ECDH_NISTP384_SIKE_P610_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_sike_p610_compressed_sha256, kexcmd(KEX_ECDH_NISTP384_SIKE_P610_COMPRESSED_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_sike_p751_sha256, kexcmd(KEX_ECDH_NISTP521_SIKE_P751_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_sike_p751_sha256, kexcmd(KEX_ECDH_NISTP521_SIKE_P751_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_sike_p751_sha256, kexcmd(KEX_ECDH_NISTP521_SIKE_P751_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_sike_p751_sha256, kexcmd(KEX_ECDH_NISTP521_SIKE_P751_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_sike_p751_compressed_sha256, kexcmd(KEX_ECDH_NISTP521_SIKE_P751_COMPRESSED_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_sike_p751_compressed_sha256, kexcmd(KEX_ECDH_NISTP521_SIKE_P751_COMPRESSED_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_sike_p751_compressed_sha256, kexcmd(KEX_ECDH_NISTP521_SIKE_P751_COMPRESSED_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_sike_p751_compressed_sha256, kexcmd(KEX_ECDH_NISTP521_SIKE_P751_COMPRESSED_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_saber_lightsaber_sha256, kexcmd(KEX_ECDH_NISTP256_SABER_LIGHTSABER_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_saber_lightsaber_sha256, kexcmd(KEX_ECDH_NISTP256_SABER_LIGHTSABER_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_saber_lightsaber_sha256, kexcmd(KEX_ECDH_NISTP256_SABER_LIGHTSABER_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_saber_lightsaber_sha256, kexcmd(KEX_ECDH_NISTP256_SABER_LIGHTSABER_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_saber_saber_sha384, kexcmd(KEX_ECDH_NISTP384_SABER_SABER_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_saber_saber_sha384, kexcmd(KEX_ECDH_NISTP384_SABER_SABER_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_saber_saber_sha384, kexcmd(KEX_ECDH_NISTP384_SABER_SABER_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_saber_saber_sha384, kexcmd(KEX_ECDH_NISTP384_SABER_SABER_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_saber_firesaber_sha512, kexcmd(KEX_ECDH_NISTP521_SABER_FIRESABER_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_saber_firesaber_sha512, kexcmd(KEX_ECDH_NISTP521_SABER_FIRESABER_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_saber_firesaber_sha512, kexcmd(KEX_ECDH_NISTP521_SABER_FIRESABER_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_saber_firesaber_sha512, kexcmd(KEX_ECDH_NISTP521_SABER_FIRESABER_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_kyber_512_sha256, kexcmd(KEX_ECDH_NISTP256_KYBER_512_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_kyber_512_sha256, kexcmd(KEX_ECDH_NISTP256_KYBER_512_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_kyber_512_sha256, kexcmd(KEX_ECDH_NISTP256_KYBER_512_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_kyber_512_sha256, kexcmd(KEX_ECDH_NISTP256_KYBER_512_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_kyber_768_sha384, kexcmd(KEX_ECDH_NISTP384_KYBER_768_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_kyber_768_sha384, kexcmd(KEX_ECDH_NISTP384_KYBER_768_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_kyber_768_sha384, kexcmd(KEX_ECDH_NISTP384_KYBER_768_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_kyber_768_sha384, kexcmd(KEX_ECDH_NISTP384_KYBER_768_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_kyber_1024_sha512, kexcmd(KEX_ECDH_NISTP521_KYBER_1024_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_kyber_1024_sha512, kexcmd(KEX_ECDH_NISTP521_KYBER_1024_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_kyber_1024_sha512, kexcmd(KEX_ECDH_NISTP521_KYBER_1024_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_kyber_1024_sha512, kexcmd(KEX_ECDH_NISTP521_KYBER_1024_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_kyber_512_90s_sha256, kexcmd(KEX_ECDH_NISTP256_KYBER_512_90S_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_kyber_512_90s_sha256, kexcmd(KEX_ECDH_NISTP256_KYBER_512_90S_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_kyber_512_90s_sha256, kexcmd(KEX_ECDH_NISTP256_KYBER_512_90S_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_kyber_512_90s_sha256, kexcmd(KEX_ECDH_NISTP256_KYBER_512_90S_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_kyber_768_90s_sha384, kexcmd(KEX_ECDH_NISTP384_KYBER_768_90S_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_kyber_768_90s_sha384, kexcmd(KEX_ECDH_NISTP384_KYBER_768_90S_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_kyber_768_90s_sha384, kexcmd(KEX_ECDH_NISTP384_KYBER_768_90S_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_kyber_768_90s_sha384, kexcmd(KEX_ECDH_NISTP384_KYBER_768_90S_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_kyber_1024_90s_sha512, kexcmd(KEX_ECDH_NISTP521_KYBER_1024_90S_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_kyber_1024_90s_sha512, kexcmd(KEX_ECDH_NISTP521_KYBER_1024_90S_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_kyber_1024_90s_sha512, kexcmd(KEX_ECDH_NISTP521_KYBER_1024_90S_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_kyber_1024_90s_sha512, kexcmd(KEX_ECDH_NISTP521_KYBER_1024_90S_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_bike_l1_sha512, kexcmd(KEX_ECDH_NISTP256_BIKE_L1_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_bike_l1_sha512, kexcmd(KEX_ECDH_NISTP256_BIKE_L1_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_bike_l1_sha512, kexcmd(KEX_ECDH_NISTP256_BIKE_L1_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_bike_l1_sha512, kexcmd(KEX_ECDH_NISTP256_BIKE_L1_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_bike_l3_sha512, kexcmd(KEX_ECDH_NISTP384_BIKE_L3_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_bike_l3_sha512, kexcmd(KEX_ECDH_NISTP384_BIKE_L3_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_bike_l3_sha512, kexcmd(KEX_ECDH_NISTP384_BIKE_L3_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_bike_l3_sha512, kexcmd(KEX_ECDH_NISTP384_BIKE_L3_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_ntru_hps2048509_sha512, kexcmd(KEX_ECDH_NISTP256_NTRU_HPS2048509_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_ntru_hps2048509_sha512, kexcmd(KEX_ECDH_NISTP256_NTRU_HPS2048509_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_ntru_hps2048509_sha512, kexcmd(KEX_ECDH_NISTP256_NTRU_HPS2048509_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_ntru_hps2048509_sha512, kexcmd(KEX_ECDH_NISTP256_NTRU_HPS2048509_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_ntru_hps2048677_sha512, kexcmd(KEX_ECDH_NISTP384_NTRU_HPS2048677_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_ntru_hps2048677_sha512, kexcmd(KEX_ECDH_NISTP384_NTRU_HPS2048677_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_ntru_hps2048677_sha512, kexcmd(KEX_ECDH_NISTP384_NTRU_HPS2048677_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_ntru_hps2048677_sha512, kexcmd(KEX_ECDH_NISTP384_NTRU_HPS2048677_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_ntru_hps4096821_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HPS4096821_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_ntru_hps4096821_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HPS4096821_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_ntru_hps4096821_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HPS4096821_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_ntru_hps4096821_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HPS4096821_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_ntru_hps40961229_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HPS40961229_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_ntru_hps40961229_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HPS40961229_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_ntru_hps40961229_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HPS40961229_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_ntru_hps40961229_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HPS40961229_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_ntru_hrss701_sha512, kexcmd(KEX_ECDH_NISTP384_NTRU_HRSS701_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_ntru_hrss701_sha512, kexcmd(KEX_ECDH_NISTP384_NTRU_HRSS701_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_ntru_hrss701_sha512, kexcmd(KEX_ECDH_NISTP384_NTRU_HRSS701_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_ntru_hrss701_sha512, kexcmd(KEX_ECDH_NISTP384_NTRU_HRSS701_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_ntru_hrss1373_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HRSS1373_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_ntru_hrss1373_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HRSS1373_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_ntru_hrss1373_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HRSS1373_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_ntru_hrss1373_sha512, kexcmd(KEX_ECDH_NISTP521_NTRU_HRSS1373_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_classic_mceliece_348864_sha256, kexcmd(KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_classic_mceliece_348864_sha256, kexcmd(KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_classic_mceliece_348864_sha256, kexcmd(KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_classic_mceliece_348864_sha256, kexcmd(KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_classic_mceliece_348864f_sha256, kexcmd(KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864F_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_classic_mceliece_348864f_sha256, kexcmd(KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864F_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_classic_mceliece_348864f_sha256, kexcmd(KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864F_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_classic_mceliece_348864f_sha256, kexcmd(KEX_ECDH_NISTP256_CLASSIC_MCELIECE_348864F_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_classic_mceliece_460896_sha512, kexcmd(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_classic_mceliece_460896_sha512, kexcmd(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_classic_mceliece_460896_sha512, kexcmd(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_classic_mceliece_460896_sha512, kexcmd(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_classic_mceliece_460896f_sha512, kexcmd(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_classic_mceliece_460896f_sha512, kexcmd(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_classic_mceliece_460896f_sha512, kexcmd(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_classic_mceliece_460896f_sha512, kexcmd(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_classic_mceliece_6688128_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_classic_mceliece_6688128_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_classic_mceliece_6688128_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_classic_mceliece_6688128_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_classic_mceliece_6688128f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128F_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_classic_mceliece_6688128f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128F_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_classic_mceliece_6688128f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128F_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_classic_mceliece_6688128f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6688128F_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_classic_mceliece_6960119_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_classic_mceliece_6960119_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_classic_mceliece_6960119_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_classic_mceliece_6960119_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_classic_mceliece_6960119f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119F_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_classic_mceliece_6960119f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119F_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_classic_mceliece_6960119f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119F_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_classic_mceliece_6960119f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_6960119F_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_classic_mceliece_8192128_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_classic_mceliece_8192128_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_classic_mceliece_8192128_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_classic_mceliece_8192128_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_classic_mceliece_8192128f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128F_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_classic_mceliece_8192128f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128F_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_classic_mceliece_8192128f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128F_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_classic_mceliece_8192128f_sha512, kexcmd(KEX_ECDH_NISTP521_CLASSIC_MCELIECE_8192128F_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_hqc_128_sha256, kexcmd(KEX_ECDH_NISTP256_HQC_128_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_hqc_128_sha256, kexcmd(KEX_ECDH_NISTP256_HQC_128_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_hqc_128_sha256, kexcmd(KEX_ECDH_NISTP256_HQC_128_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_hqc_128_sha256, kexcmd(KEX_ECDH_NISTP256_HQC_128_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_hqc_192_sha384, kexcmd(KEX_ECDH_NISTP384_HQC_192_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_hqc_192_sha384, kexcmd(KEX_ECDH_NISTP384_HQC_192_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_hqc_192_sha384, kexcmd(KEX_ECDH_NISTP384_HQC_192_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_hqc_192_sha384, kexcmd(KEX_ECDH_NISTP384_HQC_192_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_hqc_256_sha512, kexcmd(KEX_ECDH_NISTP521_HQC_256_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_hqc_256_sha512, kexcmd(KEX_ECDH_NISTP521_HQC_256_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_hqc_256_sha512, kexcmd(KEX_ECDH_NISTP521_HQC_256_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_hqc_256_sha512, kexcmd(KEX_ECDH_NISTP521_HQC_256_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_ntruprime_ntrulpr653_sha256, kexcmd(KEX_ECDH_NISTP256_NTRUPRIME_NTRULPR653_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_ntruprime_ntrulpr653_sha256, kexcmd(KEX_ECDH_NISTP256_NTRUPRIME_NTRULPR653_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_ntruprime_ntrulpr653_sha256, kexcmd(KEX_ECDH_NISTP256_NTRUPRIME_NTRULPR653_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_ntruprime_ntrulpr653_sha256, kexcmd(KEX_ECDH_NISTP256_NTRUPRIME_NTRULPR653_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp256_ntruprime_sntrup653_sha256, kexcmd(KEX_ECDH_NISTP256_NTRUPRIME_SNTRUP653_SHA256), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp256_ntruprime_sntrup653_sha256, kexcmd(KEX_ECDH_NISTP256_NTRUPRIME_SNTRUP653_SHA256), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp256_ntruprime_sntrup653_sha256, kexcmd(KEX_ECDH_NISTP256_NTRUPRIME_SNTRUP653_SHA256), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp256_ntruprime_sntrup653_sha256, kexcmd(KEX_ECDH_NISTP256_NTRUPRIME_SNTRUP653_SHA256), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_ntruprime_ntrulpr761_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR761_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_ntruprime_ntrulpr761_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR761_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_ntruprime_ntrulpr761_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR761_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_ntruprime_ntrulpr761_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR761_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_ntruprime_sntrup761_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP761_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_ntruprime_sntrup761_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP761_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_ntruprime_sntrup761_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP761_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_ntruprime_sntrup761_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP761_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_ntruprime_ntrulpr857_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR857_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_ntruprime_ntrulpr857_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR857_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_ntruprime_ntrulpr857_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR857_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_ntruprime_ntrulpr857_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_NTRULPR857_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp384_ntruprime_sntrup857_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP857_SHA384), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp384_ntruprime_sntrup857_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP857_SHA384), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp384_ntruprime_sntrup857_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP857_SHA384), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp384_ntruprime_sntrup857_sha384, kexcmd(KEX_ECDH_NISTP384_NTRUPRIME_SNTRUP857_SHA384), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_ntruprime_ntrulpr1277_sha512, kexcmd(KEX_ECDH_NISTP521_NTRUPRIME_NTRULPR1277_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_ntruprime_ntrulpr1277_sha512, kexcmd(KEX_ECDH_NISTP521_NTRUPRIME_NTRULPR1277_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_ntruprime_ntrulpr1277_sha512, kexcmd(KEX_ECDH_NISTP521_NTRUPRIME_NTRULPR1277_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_ntruprime_ntrulpr1277_sha512, kexcmd(KEX_ECDH_NISTP521_NTRUPRIME_NTRULPR1277_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, rsa_ecdh_nistp521_ntruprime_sntrup1277_sha512, kexcmd(KEX_ECDH_NISTP521_NTRUPRIME_SNTRUP1277_SHA512), setup_rsa, teardown) \
    f(client, ecdsa_256_ecdh_nistp521_ntruprime_sntrup1277_sha512, kexcmd(KEX_ECDH_NISTP521_NTRUPRIME_SNTRUP1277_SHA512), setup_ecdsa_256, teardown) \
    f(client, picnic_l1_full_ecdh_nistp521_ntruprime_sntrup1277_sha512, kexcmd(KEX_ECDH_NISTP521_NTRUPRIME_SNTRUP1277_SHA512), setup_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_nistp521_ntruprime_sntrup1277_sha512, kexcmd(KEX_ECDH_NISTP521_NTRUPRIME_SNTRUP1277_SHA512), setup_ecdsa_nistp256_picnic_l1_full, teardown)

/* Classical key exchange is used for testing the digital signature algorithms. */
#define PKDTESTS_OQSKEYAUTH(f, client, kexcmd) \
    f(client, falcon_512_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_falcon_512, teardown) \
    f(client, rsa3072_falcon_512_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_rsa3072_falcon_512, teardown) \
    f(client, ecdsa_nistp256_falcon_512_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_ecdsa_nistp256_falcon_512, teardown) \
    f(client, falcon_1024_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_falcon_1024, teardown) \
    f(client, ecdsa_nistp521_falcon_1024_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_ecdsa_nistp521_falcon_1024, teardown) \
    f(client, dilithium_3_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_dilithium_3, teardown) \
    f(client, ecdsa_nistp384_dilithium_3_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_ecdsa_nistp384_dilithium_3, teardown) \
    f(client, dilithium_2_aes_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_dilithium_2_aes, teardown) \
    f(client, rsa3072_dilithium_2_aes_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_rsa3072_dilithium_2_aes, teardown) \
    f(client, ecdsa_nistp256_dilithium_2_aes_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_ecdsa_nistp256_dilithium_2_aes, teardown) \
    f(client, dilithium_5_aes_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_dilithium_5_aes, teardown) \
    f(client, ecdsa_nistp521_dilithium_5_aes_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_ecdsa_nistp521_dilithium_5_aes, teardown) \
    f(client, picnic_l1_full_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_picnic_l1_full, teardown) \
    f(client, rsa3072_picnic_l1_full_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_rsa3072_picnic_l1_full, teardown) \
    f(client, ecdsa_nistp256_picnic_l1_full_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_ecdsa_nistp256_picnic_l1_full, teardown) \
    f(client, picnic_l3_fs_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_picnic_l3_fs, teardown) \
    f(client, ecdsa_nistp384_picnic_l3_fs_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_ecdsa_nistp384_picnic_l3_fs, teardown) \
    f(client, sphincs_haraka_128f_simple_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_sphincs_haraka_128f_simple, teardown) \
    f(client, rsa3072_sphincs_haraka_128f_simple_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_rsa3072_sphincs_haraka_128f_simple, teardown) \
    f(client, ecdsa_nistp256_sphincs_haraka_128f_simple_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_ecdsa_nistp256_sphincs_haraka_128f_simple, teardown) \
    f(client, sphincs_haraka_192f_robust_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_sphincs_haraka_192f_robust, teardown) \
    f(client, ecdsa_nistp384_sphincs_haraka_192f_robust_ecdh_sha2_nistp256, kexcmd("ecdh-sha2-nistp256"), setup_ecdsa_nistp384_sphincs_haraka_192f_robust, teardown)
///// OQS_TEMPLATE_FRAGMENT_KEX_TEST_CASES_END
#endif

#define PKDTESTS_CIPHER_COMMON(f, client, ciphercmd) \
    f(client, rsa_aes128_ctr,          ciphercmd("aes128-ctr"),    setup_rsa,        teardown) \
    f(client, rsa_aes256_ctr,          ciphercmd("aes256-ctr"),    setup_rsa,        teardown) \
    f(client, ecdsa_256_aes128_ctr,    ciphercmd("aes128-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes256_ctr,    ciphercmd("aes256-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_aes128_ctr,    ciphercmd("aes128-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes256_ctr,    ciphercmd("aes256-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_aes128_ctr,    ciphercmd("aes128-ctr"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes256_ctr,    ciphercmd("aes256-ctr"),    setup_ecdsa_521,  teardown)

#define PKDTESTS_CIPHER_FIPS(f, client, ciphercmd) \
    PKDTESTS_CIPHER_COMMON(f, client, ciphercmd) \
    f(client, rsa_aes128_cbc,          ciphercmd("aes128-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes256_cbc,          ciphercmd("aes256-cbc"),    setup_rsa,        teardown) \
    f(client, ecdsa_256_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_521,  teardown)

#ifdef HAVE_DSA
#define PKDTESTS_CIPHER(f, client, ciphercmd) \
    /* Ciphers. */ \
    PKDTESTS_CIPHER_COMMON(f, client, ciphercmd) \
    f(client, dsa_aes128_ctr,          ciphercmd("aes128-ctr"),    setup_dsa,        teardown) \
    f(client, dsa_aes256_ctr,          ciphercmd("aes256-ctr"),    setup_dsa,        teardown)
#else
#define PKDTESTS_CIPHER(f, client, ciphercmd) \
    /* Ciphers. */ \
    PKDTESTS_CIPHER_COMMON(f, client, ciphercmd)
#endif

#define CHACHA20 "chacha20-poly1305@openssh.com"
#define AES128_GCM "aes128-gcm@openssh.com"
#define AES256_GCM "aes256-gcm@openssh.com"

#define PKDTESTS_CIPHER_OPENSSHONLY_FIPS(f, client, ciphercmd) \
    f(client, rsa_aes128_gcm,          ciphercmd(AES128_GCM),      setup_rsa,        teardown) \
    f(client, rsa_aes256_gcm,          ciphercmd(AES256_GCM),      setup_rsa,        teardown) \
    f(client, ecdsa_256_aes128_gcm,    ciphercmd(AES128_GCM),      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes256_gcm,    ciphercmd(AES256_GCM),      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_aes128_gcm,    ciphercmd(AES128_GCM),      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes256_gcm,    ciphercmd(AES256_GCM),      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_aes128_gcm,    ciphercmd(AES128_GCM),      setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes256_gcm,    ciphercmd(AES256_GCM),      setup_ecdsa_521,  teardown)

#ifdef HAVE_DSA
#define PKDTESTS_CIPHER_OPENSSHONLY(f, client, ciphercmd) \
    /* Ciphers. */ \
    PKDTESTS_CIPHER_OPENSSHONLY_FIPS(f, client, ciphercmd) \
    f(client, rsa_3des_cbc,            ciphercmd("3des-cbc"),      setup_rsa,        teardown) \
    f(client, rsa_aes128_cbc,          ciphercmd("aes128-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes192_cbc,          ciphercmd("aes192-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes256_cbc,          ciphercmd("aes256-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes192_ctr,          ciphercmd("aes192-ctr"),    setup_rsa,        teardown) \
    f(client, rsa_chacha20,            ciphercmd(CHACHA20),        setup_rsa,        teardown) \
    f(client, dsa_3des_cbc,            ciphercmd("3des-cbc"),      setup_dsa,        teardown) \
    f(client, dsa_aes128_cbc,          ciphercmd("aes128-cbc"),    setup_dsa,        teardown) \
    f(client, dsa_aes192_cbc,          ciphercmd("aes192-cbc"),    setup_dsa,        teardown) \
    f(client, dsa_aes256_cbc,          ciphercmd("aes256-cbc"),    setup_dsa,        teardown) \
    f(client, dsa_aes192_ctr,          ciphercmd("aes192-ctr"),    setup_dsa,        teardown) \
    f(client, dsa_chacha20,            ciphercmd(CHACHA20),        setup_dsa,        teardown) \
    f(client, dsa_aes128_gcm,          ciphercmd(AES128_GCM),      setup_dsa,        teardown) \
    f(client, dsa_aes256_gcm,          ciphercmd(AES256_GCM),      setup_dsa,        teardown) \
    f(client, ed25519_3des_cbc,        ciphercmd("3des-cbc"),      setup_ed25519,    teardown) \
    f(client, ed25519_aes128_cbc,      ciphercmd("aes128-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes128_ctr,      ciphercmd("aes128-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes256_cbc,      ciphercmd("aes256-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes256_ctr,      ciphercmd("aes256-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes192_cbc,      ciphercmd("aes192-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes192_ctr,      ciphercmd("aes192-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_chacha20,        ciphercmd(CHACHA20),        setup_ed25519,    teardown) \
    f(client, ed25519_aes128_gcm,      ciphercmd(AES128_GCM),      setup_ed25519,    teardown) \
    f(client, ed25519_aes256_gcm,      ciphercmd(AES256_GCM),      setup_ed25519,    teardown) \
    f(client, ecdsa_256_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_521,  teardown)
#else
#define PKDTESTS_CIPHER_OPENSSHONLY(f, client, ciphercmd) \
    /* Ciphers. */ \
    PKDTESTS_CIPHER_OPENSSHONLY_FIPS(f, client, ciphercmd) \
    f(client, rsa_3des_cbc,            ciphercmd("3des-cbc"),      setup_rsa,        teardown) \
    f(client, rsa_aes128_cbc,          ciphercmd("aes128-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes192_cbc,          ciphercmd("aes192-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes256_cbc,          ciphercmd("aes256-cbc"),    setup_rsa,        teardown) \
    f(client, rsa_aes192_ctr,          ciphercmd("aes192-ctr"),    setup_rsa,        teardown) \
    f(client, rsa_chacha20,            ciphercmd(CHACHA20),        setup_rsa,        teardown) \
    f(client, ed25519_3des_cbc,        ciphercmd("3des-cbc"),      setup_ed25519,    teardown) \
    f(client, ed25519_aes128_cbc,      ciphercmd("aes128-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes128_ctr,      ciphercmd("aes128-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes256_cbc,      ciphercmd("aes256-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes256_ctr,      ciphercmd("aes256-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes192_cbc,      ciphercmd("aes192-cbc"),    setup_ed25519,    teardown) \
    f(client, ed25519_aes192_ctr,      ciphercmd("aes192-ctr"),    setup_ed25519,    teardown) \
    f(client, ed25519_chacha20,        ciphercmd(CHACHA20),        setup_ed25519,    teardown) \
    f(client, ecdsa_256_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_3des_cbc,      ciphercmd("3des-cbc"),      setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes128_cbc,    ciphercmd("aes128-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes192_cbc,    ciphercmd("aes192-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes256_cbc,    ciphercmd("aes256-cbc"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_aes192_ctr,    ciphercmd("aes192-ctr"),    setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_chacha20,      ciphercmd(CHACHA20),        setup_ecdsa_521,  teardown)
#endif


#define PKDTESTS_MAC_FIPS(f, client, maccmd) \
    f(client, ecdsa_256_hmac_sha1,          maccmd("hmac-sha1"),                      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_hmac_sha2_256,      maccmd("hmac-sha2-256"),                  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_hmac_sha1,          maccmd("hmac-sha1"),                      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_hmac_sha2_256,      maccmd("hmac-sha2-256"),                  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_hmac_sha1,          maccmd("hmac-sha1"),                      setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_hmac_sha2_256,      maccmd("hmac-sha2-256"),                  setup_ecdsa_521,  teardown) \
    f(client, rsa_hmac_sha1,                maccmd("hmac-sha1"),                      setup_rsa,        teardown) \
    f(client, rsa_hmac_sha2_256,            maccmd("hmac-sha2-256"),                  setup_rsa,        teardown)

#define PKDTESTS_MAC_OPENSSHONLY_FIPS(f, client, maccmd) \
    f(client, ecdsa_256_hmac_sha1_etm,      maccmd("hmac-sha1-etm@openssh.com"),      setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_hmac_sha2_256_etm,  maccmd("hmac-sha2-256-etm@openssh.com"),  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_hmac_sha2_512,      maccmd("hmac-sha2-512"),                  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_256_hmac_sha2_512_etm,  maccmd("hmac-sha2-512-etm@openssh.com"),  setup_ecdsa_256,  teardown) \
    f(client, ecdsa_384_hmac_sha1_etm,      maccmd("hmac-sha1-etm@openssh.com"),      setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_hmac_sha2_256_etm,  maccmd("hmac-sha2-256-etm@openssh.com"),  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_hmac_sha2_512,      maccmd("hmac-sha2-512"),                  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_384_hmac_sha2_512_etm,  maccmd("hmac-sha2-512-etm@openssh.com"),  setup_ecdsa_384,  teardown) \
    f(client, ecdsa_521_hmac_sha1_etm,      maccmd("hmac-sha1-etm@openssh.com"),      setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_hmac_sha2_256_etm,  maccmd("hmac-sha2-256-etm@openssh.com"),  setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_hmac_sha2_512,      maccmd("hmac-sha2-512"),                  setup_ecdsa_521,  teardown) \
    f(client, ecdsa_521_hmac_sha2_512_etm,  maccmd("hmac-sha2-512-etm@openssh.com"),  setup_ecdsa_521,  teardown) \
    f(client, rsa_hmac_sha1_etm,            maccmd("hmac-sha1-etm@openssh.com"),      setup_rsa,        teardown) \
    f(client, rsa_hmac_sha2_256_etm,        maccmd("hmac-sha2-256-etm@openssh.com"),  setup_rsa,        teardown) \
    f(client, rsa_hmac_sha2_512,            maccmd("hmac-sha2-512"),                  setup_rsa,        teardown) \
    f(client, rsa_hmac_sha2_512_etm,        maccmd("hmac-sha2-512-etm@openssh.com"),  setup_rsa,        teardown)

#ifdef HAVE_DSA
#define PKDTESTS_MAC(f, client, maccmd) \
    /* MACs. */ \
    PKDTESTS_MAC_FIPS(f, client, maccmd) \
    f(client, dsa_hmac_sha1,                maccmd("hmac-sha1"),                      setup_dsa,        teardown) \
    f(client, dsa_hmac_sha2_256,            maccmd("hmac-sha2-256"),                  setup_dsa,        teardown)
#define PKDTESTS_MAC_OPENSSHONLY(f, client, maccmd) \
    PKDTESTS_MAC_OPENSSHONLY_FIPS(f, client, maccmd) \
    f(client, dsa_hmac_sha1_etm,            maccmd("hmac-sha1-etm@openssh.com"),      setup_dsa,        teardown) \
    f(client, dsa_hmac_sha2_256_etm,        maccmd("hmac-sha2-256-etm@openssh.com"),  setup_dsa,        teardown) \
    f(client, dsa_hmac_sha2_512,            maccmd("hmac-sha2-512"),                  setup_dsa,        teardown) \
    f(client, dsa_hmac_sha2_512_etm,        maccmd("hmac-sha2-512-etm@openssh.com"),  setup_dsa,        teardown) \
    f(client, ed25519_hmac_sha1,            maccmd("hmac-sha1"),                      setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha1_etm,        maccmd("hmac-sha1-etm@openssh.com"),      setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_256,        maccmd("hmac-sha2-256"),                  setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_256_etm,    maccmd("hmac-sha2-256-etm@openssh.com"),  setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_512,        maccmd("hmac-sha2-512"),                  setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_512_etm,    maccmd("hmac-sha2-512-etm@openssh.com"),  setup_ed25519,    teardown)
#else
#define PKDTESTS_MAC(f, client, maccmd) \
    /* MACs. */ \
    PKDTESTS_MAC_FIPS(f, client, maccmd)
#define PKDTESTS_MAC_OPENSSHONLY(f, client, maccmd) \
    PKDTESTS_MAC_OPENSSHONLY_FIPS(f, client, maccmd) \
    f(client, ed25519_hmac_sha1,            maccmd("hmac-sha1"),                      setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha1_etm,        maccmd("hmac-sha1-etm@openssh.com"),      setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_256,        maccmd("hmac-sha2-256"),                  setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_256_etm,    maccmd("hmac-sha2-256-etm@openssh.com"),  setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_512,        maccmd("hmac-sha2-512"),                  setup_ed25519,    teardown) \
    f(client, ed25519_hmac_sha2_512_etm,    maccmd("hmac-sha2-512-etm@openssh.com"),  setup_ed25519,    teardown)
#endif


#define PKDTESTS_HOSTKEY_OPENSSHONLY_FIPS(f, client, hkcmd) \
    f(client, rsa_sha2_256,     hkcmd("rsa-sha2-256"),               setup_rsa,    teardown) \
    f(client, rsa_sha2_512,     hkcmd("rsa-sha2-512"),               setup_rsa,    teardown) \
    f(client, rsa_sha2_256_512, hkcmd("rsa-sha2-256,rsa-sha2-512"),  setup_rsa,    teardown) \
    f(client, rsa_sha2_512_256, hkcmd("rsa-sha2-512,rsa-sha2-256"),  setup_rsa,    teardown)

#define PKDTESTS_HOSTKEY_OPENSSHONLY(f, client, hkcmd) \
    PKDTESTS_HOSTKEY_OPENSSHONLY_FIPS(f, client, hkcmd)

static void torture_pkd_client_noop(void **state) {
    struct pkd_state *pstate = (struct pkd_state *) (*state);
    (void) pstate;
    return;
}

static void torture_pkd_runtest(const char *testname,
                                const char *testcmd)
{
    int i, rc;
    char logfile[1024] = { 0 };
    int iterations =
        (pkd_dargs.opts.iterations != 0) ? pkd_dargs.opts.iterations
                                         : DEFAULT_ITERATIONS;

    for (i = 0; i < iterations; i++) {
        rc = system_checked(testcmd);
        assert_int_equal(rc, 0);
    }

    /* Asserts did not trip: cleanup logs. */
    snprintf(&logfile[0], sizeof(logfile), "%s.out", testname);
    unlink(logfile);
    snprintf(&logfile[0], sizeof(logfile), "%s.err", testname);
    unlink(logfile);
}

/*
 * Though each keytest function body is the same, separate functions are
 * defined here to result in distinct output when running the tests.
 */

#define emit_keytest(client, testname, sshcmd, setup, teardown) \
    static void torture_pkd_## client ## _ ## testname(void **state) { \
        const char *tname = "torture_pkd_" #client "_" #testname;      \
        char testcmd[3072] = { 0 };                                    \
        (void) state;                                                  \
        snprintf(&testcmd[0], sizeof(testcmd), sshcmd, tname, tname);  \
        torture_pkd_runtest(tname, testcmd);                           \
    }

/*
 * Actual test functions are emitted here.
 */

#ifdef HAVE_DSA
#define CLIENT_ID_FILE OPENSSH_DSA_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, openssh_dsa, OPENSSH_CMD)
PKDTESTS_DEFAULT(emit_keytest, openssh_cert_dsa, OPENSSH_CERT_CMD)
PKDTESTS_DEFAULT_OPENSSHONLY(emit_keytest, openssh_dsa, OPENSSH_CMD)
PKDTESTS_KEX(emit_keytest, openssh_dsa, OPENSSH_KEX_CMD)
PKDTESTS_KEX_OPENSSHONLY(emit_keytest, openssh_dsa, OPENSSH_KEX_CMD)
PKDTESTS_CIPHER(emit_keytest, openssh_dsa, OPENSSH_CIPHER_CMD)
PKDTESTS_CIPHER_OPENSSHONLY(emit_keytest, openssh_dsa, OPENSSH_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, openssh_dsa, OPENSSH_MAC_CMD)
PKDTESTS_MAC_OPENSSHONLY(emit_keytest, openssh_dsa, OPENSSH_MAC_CMD)
#undef CLIENT_ID_FILE
#endif

#define CLIENT_ID_FILE OPENSSH_RSA_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, openssh_rsa, OPENSSH_CMD)
PKDTESTS_DEFAULT(emit_keytest, openssh_cert_rsa, OPENSSH_CERT_CMD)
PKDTESTS_DEFAULT(emit_keytest, openssh_sha256_cert_rsa, OPENSSH_SHA256_CERT_CMD)
PKDTESTS_DEFAULT_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_CMD)
PKDTESTS_KEX(emit_keytest, openssh_rsa, OPENSSH_KEX_CMD)
PKDTESTS_KEX_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_KEX_CMD)
PKDTESTS_CIPHER(emit_keytest, openssh_rsa, OPENSSH_CIPHER_CMD)
PKDTESTS_CIPHER_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, openssh_rsa, OPENSSH_MAC_CMD)
PKDTESTS_MAC_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_MAC_CMD)
PKDTESTS_HOSTKEY_OPENSSHONLY(emit_keytest, openssh_rsa, OPENSSH_HOSTKEY_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA256_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, openssh_e256, OPENSSH_CMD)
PKDTESTS_DEFAULT(emit_keytest, openssh_cert_e256, OPENSSH_CERT_CMD)
PKDTESTS_DEFAULT_OPENSSHONLY(emit_keytest, openssh_e256, OPENSSH_CMD)
PKDTESTS_KEX(emit_keytest, openssh_e256, OPENSSH_KEX_CMD)
PKDTESTS_KEX_OPENSSHONLY(emit_keytest, openssh_e256, OPENSSH_KEX_CMD)
PKDTESTS_CIPHER(emit_keytest, openssh_e256, OPENSSH_CIPHER_CMD)
PKDTESTS_CIPHER_OPENSSHONLY(emit_keytest, openssh_e256, OPENSSH_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, openssh_e256, OPENSSH_MAC_CMD)
PKDTESTS_MAC_OPENSSHONLY(emit_keytest, openssh_e256, OPENSSH_MAC_CMD)
#undef CLIENT_ID_FILE

/* Could add these passes, too: */
//#define CLIENT_ID_FILE OPENSSH_ECDSA384_TESTKEY
//#define CLIENT_ID_FILE OPENSSH_ECDSA521_TESTKEY

#define CLIENT_ID_FILE OPENSSH_ED25519_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, openssh_ed, OPENSSH_CMD)
PKDTESTS_DEFAULT(emit_keytest, openssh_cert_ed, OPENSSH_CERT_CMD)
PKDTESTS_DEFAULT_OPENSSHONLY(emit_keytest, openssh_ed, OPENSSH_CMD)
PKDTESTS_KEX(emit_keytest, openssh_ed, OPENSSH_KEX_CMD)
PKDTESTS_KEX_OPENSSHONLY(emit_keytest, openssh_ed, OPENSSH_KEX_CMD)
PKDTESTS_CIPHER(emit_keytest, openssh_ed, OPENSSH_CIPHER_CMD)
PKDTESTS_CIPHER_OPENSSHONLY(emit_keytest, openssh_ed, OPENSSH_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, openssh_ed, OPENSSH_MAC_CMD)
PKDTESTS_MAC_OPENSSHONLY(emit_keytest, openssh_ed, OPENSSH_MAC_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE DROPBEAR_RSA_TESTKEY
PKDTESTS_DEFAULT(emit_keytest, dropbear, DROPBEAR_CMD)
PKDTESTS_CIPHER(emit_keytest, dropbear, DROPBEAR_CIPHER_CMD)
PKDTESTS_MAC(emit_keytest, dropbear, DROPBEAR_MAC_CMD)
#undef CLIENT_ID_FILE

#ifdef WITH_POST_QUANTUM_CRYPTO

#define CLIENT_ID_FILE OPENSSH_RSA_TESTKEY
PKDTESTS_KEX_OQS_PUREPQ(emit_keytest, openssh_rsa, OPENSSH_KEX_CMD)
PKDTESTS_KEX_OQS_HYBRID(emit_keytest, openssh_rsa, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

///// OQS_TEMPLATE_FRAGMENT_EMIT_KEYTESTS_START
#define CLIENT_ID_FILE OPENSSH_FALCON_512_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_falcon_512, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_RSA3072_FALCON_512_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_rsa3072_falcon_512, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA_NISTP256_FALCON_512_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_ecdsa_nistp256_falcon_512, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE
#define CLIENT_ID_FILE OPENSSH_FALCON_1024_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_falcon_1024, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA_NISTP521_FALCON_1024_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_ecdsa_nistp521_falcon_1024, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE
#define CLIENT_ID_FILE OPENSSH_DILITHIUM_3_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_dilithium_3, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA_NISTP384_DILITHIUM_3_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_ecdsa_nistp384_dilithium_3, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE
#define CLIENT_ID_FILE OPENSSH_DILITHIUM_2_AES_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_dilithium_2_aes, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_RSA3072_DILITHIUM_2_AES_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_rsa3072_dilithium_2_aes, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA_NISTP256_DILITHIUM_2_AES_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_ecdsa_nistp256_dilithium_2_aes, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE
#define CLIENT_ID_FILE OPENSSH_DILITHIUM_5_AES_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_dilithium_5_aes, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA_NISTP521_DILITHIUM_5_AES_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_ecdsa_nistp521_dilithium_5_aes, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE
#define CLIENT_ID_FILE OPENSSH_PICNIC_L1_FULL_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_picnic_l1_full, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_RSA3072_PICNIC_L1_FULL_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_rsa3072_picnic_l1_full, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA_NISTP256_PICNIC_L1_FULL_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_ecdsa_nistp256_picnic_l1_full, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE
#define CLIENT_ID_FILE OPENSSH_PICNIC_L3_FS_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_picnic_l3_fs, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA_NISTP384_PICNIC_L3_FS_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_ecdsa_nistp384_picnic_l3_fs, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE
#define CLIENT_ID_FILE OPENSSH_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_sphincs_haraka_128f_simple, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_RSA3072_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_rsa3072_sphincs_haraka_128f_simple, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA_NISTP256_SPHINCS_HARAKA_128F_SIMPLE_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_ecdsa_nistp256_sphincs_haraka_128f_simple, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE
#define CLIENT_ID_FILE OPENSSH_SPHINCS_HARAKA_192F_ROBUST_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_sphincs_haraka_192f_robust, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE

#define CLIENT_ID_FILE OPENSSH_ECDSA_NISTP384_SPHINCS_HARAKA_192F_ROBUST_TESTKEY
PKDTESTS_OQSKEYAUTH(emit_keytest, openssh_ecdsa_nistp384_sphincs_haraka_192f_robust, OPENSSH_KEX_CMD)
#undef CLIENT_ID_FILE
///// OQS_TEMPLATE_FRAGMENT_EMIT_KEYTESTS_END
#endif
/*
 * Define an array of testname strings mapped to their associated
 * test function.  Enables running tests individually by name from
 * the command line.
 */

#define emit_testmap(client, testname, sshcmd, setup, teardown) \
    { "torture_pkd_" #client "_" #testname,                     \
      emit_unit_test(client, testname, sshcmd, setup, teardown) },

#define emit_unit_test(client, testname, sshcmd, setup, teardown) \
    cmocka_unit_test_setup_teardown(torture_pkd_ ## client ## _ ## testname, \
                                    torture_pkd_ ## setup, \
                                    torture_pkd_ ## teardown)

#define emit_unit_test_comma(client, testname, sshcmd, setup, teardown) \
    emit_unit_test(client, testname, sshcmd, setup, teardown),

struct {
    const char *testname;
    const struct CMUnitTest test;
} testmap[] = {
    /* OpenSSH */
#ifdef HAVE_DSA
    PKDTESTS_DEFAULT(emit_testmap, openssh_dsa, OPENSSH_CMD)
    PKDTESTS_DEFAULT(emit_testmap, openssh_cert_dsa, OPENSSH_CERT_CMD)
    PKDTESTS_DEFAULT_OPENSSHONLY(emit_testmap, openssh_dsa, OPENSSH_CMD)
    PKDTESTS_KEX(emit_testmap, openssh_dsa, OPENSSH_KEX_CMD)
    PKDTESTS_KEX_OPENSSHONLY(emit_testmap, openssh_dsa, OPENSSH_KEX_CMD)
    PKDTESTS_CIPHER(emit_testmap, openssh_dsa, OPENSSH_CIPHER_CMD)
    PKDTESTS_CIPHER_OPENSSHONLY(emit_testmap, openssh_dsa, OPENSSH_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, openssh_dsa, OPENSSH_MAC_CMD)
    PKDTESTS_MAC_OPENSSHONLY(emit_testmap, openssh_dsa, OPENSSH_MAC_CMD)
#endif

    PKDTESTS_DEFAULT(emit_testmap, openssh_rsa, OPENSSH_CMD)
    PKDTESTS_DEFAULT(emit_testmap, openssh_cert_rsa, OPENSSH_CERT_CMD)
    PKDTESTS_DEFAULT(emit_testmap, openssh_sha256_cert_rsa, OPENSSH_SHA256_CERT_CMD)
    PKDTESTS_DEFAULT_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_CMD)
    PKDTESTS_KEX(emit_testmap, openssh_rsa, OPENSSH_KEX_CMD)
    PKDTESTS_KEX_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_KEX_CMD)
    PKDTESTS_CIPHER(emit_testmap, openssh_rsa, OPENSSH_CIPHER_CMD)
    PKDTESTS_CIPHER_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, openssh_rsa, OPENSSH_MAC_CMD)
    PKDTESTS_MAC_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_MAC_CMD)
    PKDTESTS_HOSTKEY_OPENSSHONLY(emit_testmap, openssh_rsa, OPENSSH_HOSTKEY_CMD)

    PKDTESTS_DEFAULT(emit_testmap, openssh_e256, OPENSSH_CMD)
    PKDTESTS_DEFAULT(emit_testmap, openssh_cert_e256, OPENSSH_CERT_CMD)
    PKDTESTS_DEFAULT_OPENSSHONLY(emit_testmap, openssh_e256, OPENSSH_CMD)
    PKDTESTS_KEX(emit_testmap, openssh_e256, OPENSSH_KEX_CMD)
    PKDTESTS_KEX_OPENSSHONLY(emit_testmap, openssh_e256, OPENSSH_KEX_CMD)
    PKDTESTS_CIPHER(emit_testmap, openssh_e256, OPENSSH_CIPHER_CMD)
    PKDTESTS_CIPHER_OPENSSHONLY(emit_testmap, openssh_e256, OPENSSH_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, openssh_e256, OPENSSH_MAC_CMD)
    PKDTESTS_MAC_OPENSSHONLY(emit_testmap, openssh_e256, OPENSSH_MAC_CMD)

    PKDTESTS_DEFAULT(emit_testmap, openssh_ed, OPENSSH_CMD)
    PKDTESTS_DEFAULT(emit_testmap, openssh_cert_ed, OPENSSH_CERT_CMD)
    PKDTESTS_DEFAULT_OPENSSHONLY(emit_testmap, openssh_ed, OPENSSH_CMD)
    PKDTESTS_KEX(emit_testmap, openssh_ed, OPENSSH_KEX_CMD)
    PKDTESTS_KEX_OPENSSHONLY(emit_testmap, openssh_ed, OPENSSH_KEX_CMD)
    PKDTESTS_CIPHER(emit_testmap, openssh_ed, OPENSSH_CIPHER_CMD)
    PKDTESTS_CIPHER_OPENSSHONLY(emit_testmap, openssh_ed, OPENSSH_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, openssh_ed, OPENSSH_MAC_CMD)
    PKDTESTS_MAC_OPENSSHONLY(emit_testmap, openssh_ed, OPENSSH_MAC_CMD)

    /* Dropbear */
    PKDTESTS_DEFAULT(emit_testmap, dropbear, DROPBEAR_CMD)
    PKDTESTS_CIPHER(emit_testmap, dropbear, DROPBEAR_CIPHER_CMD)
    PKDTESTS_MAC(emit_testmap, dropbear, DROPBEAR_MAC_CMD)

#ifdef WITH_POST_QUANTUM_CRYPTO
    /* OQS */

    PKDTESTS_KEX_OQS_PUREPQ(emit_testmap, openssh_rsa, OPENSSH_KEX_CMD)
    PKDTESTS_KEX_OQS_HYBRID(emit_testmap, openssh_rsa, OPENSSH_KEX_CMD)

///// OQS_TEMPLATE_FRAGMENT_EMIT_TESTMAP_START
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_falcon_512, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_rsa3072_falcon_512, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_ecdsa_nistp256_falcon_512, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_falcon_1024, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_ecdsa_nistp521_falcon_1024, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_dilithium_3, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_ecdsa_nistp384_dilithium_3, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_dilithium_2_aes, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_rsa3072_dilithium_2_aes, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_ecdsa_nistp256_dilithium_2_aes, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_dilithium_5_aes, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_ecdsa_nistp521_dilithium_5_aes, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_picnic_l1_full, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_rsa3072_picnic_l1_full, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_ecdsa_nistp256_picnic_l1_full, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_picnic_l3_fs, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_ecdsa_nistp384_picnic_l3_fs, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_sphincs_haraka_128f_simple, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_rsa3072_sphincs_haraka_128f_simple, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_ecdsa_nistp256_sphincs_haraka_128f_simple, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_sphincs_haraka_192f_robust, OPENSSH_KEX_CMD)
    PKDTESTS_OQSKEYAUTH(emit_testmap, openssh_ecdsa_nistp384_sphincs_haraka_192f_robust, OPENSSH_KEX_CMD)
///// OQS_TEMPLATE_FRAGMENT_EMIT_TESTMAP_END
#endif

    /* Noop */
    emit_testmap(client, noop, "", setup_noop, teardown)

    /* NULL tail entry */
    { .testname = NULL,
      .test = { .name = NULL,
                .test_func = NULL,
                .setup_func = NULL,
                .teardown_func = NULL } }
};

static int pkd_run_tests(void) {
    int rc = -1;
    int tindex = 0;

    const struct CMUnitTest openssh_tests[] = {
#ifdef HAVE_DSA
        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_dsa, OPENSSH_CMD)
        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_cert_dsa, OPENSSH_CERT_CMD)
        PKDTESTS_DEFAULT_OPENSSHONLY(emit_unit_test_comma, openssh_dsa, OPENSSH_CMD)
        PKDTESTS_KEX(emit_unit_test_comma, openssh_dsa, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, openssh_dsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY(emit_unit_test_comma, openssh_dsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, openssh_dsa, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY(emit_unit_test_comma, openssh_dsa, OPENSSH_MAC_CMD)
#endif

        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_rsa, OPENSSH_CMD)
        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_cert_rsa, OPENSSH_CERT_CMD)
        PKDTESTS_DEFAULT_FIPS(emit_unit_test_comma, openssh_sha256_cert_rsa,
                              OPENSSH_SHA256_CERT_CMD)
        PKDTESTS_DEFAULT_OPENSSHONLY(emit_unit_test_comma, openssh_rsa, OPENSSH_CMD)
        PKDTESTS_KEX(emit_unit_test_comma, openssh_rsa, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, openssh_rsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY(emit_unit_test_comma, openssh_rsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, openssh_rsa, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY(emit_unit_test_comma, openssh_rsa, OPENSSH_MAC_CMD)

        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_e256, OPENSSH_CMD)
        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_cert_e256, OPENSSH_CERT_CMD)
        PKDTESTS_DEFAULT_OPENSSHONLY(emit_unit_test_comma, openssh_e256, OPENSSH_CMD)
        PKDTESTS_KEX(emit_unit_test_comma, openssh_e256, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, openssh_e256, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY(emit_unit_test_comma, openssh_e256, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, openssh_e256, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY(emit_unit_test_comma, openssh_e256, OPENSSH_MAC_CMD)

        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_ed, OPENSSH_CMD)
        PKDTESTS_DEFAULT(emit_unit_test_comma, openssh_cert_ed, OPENSSH_CERT_CMD)
        PKDTESTS_DEFAULT_OPENSSHONLY(emit_unit_test_comma, openssh_ed, OPENSSH_CMD)
        PKDTESTS_KEX(emit_unit_test_comma, openssh_ed, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, openssh_ed, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY(emit_unit_test_comma, openssh_ed, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, openssh_ed, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY(emit_unit_test_comma, openssh_ed, OPENSSH_MAC_CMD)
    };

    const struct CMUnitTest dropbear_tests[] = {
        PKDTESTS_DEFAULT(emit_unit_test_comma, dropbear, DROPBEAR_CMD)
        PKDTESTS_CIPHER(emit_unit_test_comma, dropbear, DROPBEAR_CIPHER_CMD)
        PKDTESTS_MAC(emit_unit_test_comma, dropbear, DROPBEAR_MAC_CMD)
    };

    const struct CMUnitTest openssh_fips_tests[] = {
        PKDTESTS_DEFAULT_FIPS(emit_unit_test_comma, openssh_rsa, OPENSSH_CMD)
        PKDTESTS_DEFAULT_FIPS(emit_unit_test_comma, openssh_sha256_cert_rsa,
                              OPENSSH_SHA256_CERT_CMD)
        PKDTESTS_KEX_FIPS(emit_unit_test_comma, openssh_rsa, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER_FIPS(emit_unit_test_comma, openssh_rsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY_FIPS(emit_unit_test_comma, openssh_rsa, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC_FIPS(emit_unit_test_comma, openssh_rsa, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY_FIPS(emit_unit_test_comma, openssh_rsa, OPENSSH_MAC_CMD)

        PKDTESTS_DEFAULT_FIPS(emit_unit_test_comma, openssh_e256, OPENSSH_CMD)
        PKDTESTS_DEFAULT_FIPS(emit_unit_test_comma, openssh_cert_e256, OPENSSH_CERT_CMD)
        PKDTESTS_KEX_FIPS(emit_unit_test_comma, openssh_e256, OPENSSH_KEX_CMD)
        PKDTESTS_CIPHER_FIPS(emit_unit_test_comma, openssh_e256, OPENSSH_CIPHER_CMD)
        PKDTESTS_CIPHER_OPENSSHONLY_FIPS(emit_unit_test_comma, openssh_e256, OPENSSH_CIPHER_CMD)
        PKDTESTS_MAC_FIPS(emit_unit_test_comma, openssh_e256, OPENSSH_MAC_CMD)
        PKDTESTS_MAC_OPENSSHONLY_FIPS(emit_unit_test_comma, openssh_e256, OPENSSH_MAC_CMD)
    };

    const struct CMUnitTest noop_tests[] = {
        emit_unit_test(client, noop, "", setup_noop, teardown)
    };

#ifdef WITH_POST_QUANTUM_CRYPTO

    const struct CMUnitTest oqs_pq_kex_tests[] = {
        PKDTESTS_KEX_OQS_PUREPQ(emit_unit_test_comma, openssh_rsa, OPENSSH_KEX_CMD)
        PKDTESTS_KEX_OQS_HYBRID(emit_unit_test_comma, openssh_rsa, OPENSSH_KEX_CMD)
    };

    const struct CMUnitTest oqs_keyauth_tests[] = {
///// OQS_TEMPLATE_FRAGMENT_EMIT_UNIT_TESTS_START
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_falcon_512, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_rsa3072_falcon_512, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_ecdsa_nistp256_falcon_512, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_falcon_1024, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_ecdsa_nistp521_falcon_1024, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_dilithium_3, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_ecdsa_nistp384_dilithium_3, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_dilithium_2_aes, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_rsa3072_dilithium_2_aes, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_ecdsa_nistp256_dilithium_2_aes, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_dilithium_5_aes, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_ecdsa_nistp521_dilithium_5_aes, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_picnic_l1_full, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_rsa3072_picnic_l1_full, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_ecdsa_nistp256_picnic_l1_full, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_picnic_l3_fs, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_ecdsa_nistp384_picnic_l3_fs, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_sphincs_haraka_128f_simple, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_rsa3072_sphincs_haraka_128f_simple, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_ecdsa_nistp256_sphincs_haraka_128f_simple, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_sphincs_haraka_192f_robust, OPENSSH_KEX_CMD)
        PKDTESTS_OQSKEYAUTH(emit_unit_test_comma, openssh_ecdsa_nistp384_sphincs_haraka_192f_robust, OPENSSH_KEX_CMD)
///// OQS_TEMPLATE_FRAGMENT_EMIT_UNIT_TESTS_END
    };
#endif

    /* Test list is populated depending on which clients are enabled. */
    struct CMUnitTest all_tests[(sizeof(openssh_tests) / sizeof(openssh_tests[0])) +
                                (sizeof(dropbear_tests) / sizeof(dropbear_tests[0])) +
                                (sizeof(noop_tests) / sizeof(noop_tests[0]))
#ifdef WITH_POST_QUANTUM_CRYPTO
                              + (sizeof(oqs_pq_kex_tests) / sizeof(oqs_pq_kex_tests[0]))
                              + (sizeof(oqs_keyauth_tests) / sizeof(oqs_keyauth_tests[0]))
#endif
                               ];

    memset(&all_tests[0], 0x0, sizeof(all_tests));

#ifdef WITH_POST_QUANTUM_CRYPTO
    printf("Post-quantum cryptography is enabled. If keys from a previous run were not preserved, there can be\n"
           "a delay of up to a few minutes while keys are generated before tests run. This is normal.\n");
#endif

    /* Generate client keys and populate test list for each enabled client. */
    if (is_openssh_client_enabled()) {
        setup_openssh_client_keys();
        if (ssh_fips_mode()) {
            memcpy(&all_tests[tindex], &openssh_fips_tests[0], sizeof(openssh_fips_tests));
            tindex += (sizeof(openssh_fips_tests) / sizeof(openssh_fips_tests[0]));
        } else {
            memcpy(&all_tests[tindex], &openssh_tests[0], sizeof(openssh_tests));
            tindex += (sizeof(openssh_tests) / sizeof(openssh_tests[0]));
#ifdef WITH_POST_QUANTUM_CRYPTO
            memcpy(&all_tests[tindex], &oqs_pq_kex_tests[0], sizeof(oqs_pq_kex_tests));
            tindex += (sizeof(oqs_pq_kex_tests) / sizeof(oqs_pq_kex_tests[0]));
            memcpy(&all_tests[tindex], &oqs_keyauth_tests[0], sizeof(oqs_keyauth_tests));
            tindex += (sizeof(oqs_keyauth_tests) / sizeof(oqs_keyauth_tests[0]));
#endif
        }
    }
    
    if (is_dropbear_client_enabled()) {
        setup_dropbear_client_rsa_key();
        if (!ssh_fips_mode()) {
            memcpy(&all_tests[tindex], &dropbear_tests[0], sizeof(dropbear_tests));
            tindex += (sizeof(dropbear_tests) / sizeof(dropbear_tests[0]));
        }
    }

    memcpy(&all_tests[tindex], &noop_tests[0], sizeof(noop_tests));
    tindex += (sizeof(noop_tests) / sizeof(noop_tests[0]));

    if ((pkd_dargs.opts.testname == NULL) &&
        (pkd_dargs.opts.testmatch == NULL)) {
        rc = _cmocka_run_group_tests("all tests", all_tests, tindex, NULL, NULL);
    } else {
        size_t i = 0;
        size_t num_found = 0;
        const char *testname = pkd_dargs.opts.testname;
        const char *testmatch = pkd_dargs.opts.testmatch;

        struct CMUnitTest matching_tests[sizeof(all_tests)];
        memset(&matching_tests[0], 0x0, sizeof(matching_tests));

        while (testmap[i].testname != NULL) {
            if ((testname != NULL) &&
                (strcmp(testmap[i].testname, testname) == 0)) {
                memcpy(&matching_tests[0],
                       &testmap[i].test,
                       sizeof(struct CMUnitTest));
                num_found += 1;
                break;
            }

            if ((testmatch != NULL) &&
                (strstr(testmap[i].testname, testmatch) != NULL)) {
                memcpy(&matching_tests[num_found],
                       &testmap[i].test,
                       sizeof(struct CMUnitTest));
                num_found += 1;
            }

            i += 1;
        }

        if (num_found > 0) {
            rc = _cmocka_run_group_tests("found", matching_tests, num_found, NULL, NULL);
        } else {
            fprintf(stderr, "Did not find test '%s'\n", testname);
        }
    }

    /* Clean up client keys for each enabled client, unless user has chosen to preserve them. */
    if (!pkd_dargs.opts.preserve_keys) {
        if (is_dropbear_client_enabled()) {
            cleanup_dropbear_client_rsa_key();
        }

        if (is_openssh_client_enabled()) {
            cleanup_openssh_client_keys();
        }

        /* Clean up any server keys that were generated. */
        cleanup_rsa_key();
        cleanup_ecdsa_keys();
        if (!ssh_fips_mode()) {
            cleanup_ed25519_key();
#ifdef HAVE_DSA
            cleanup_dsa_key();
#endif
#ifdef WITH_POST_QUANTUM_CRYPTO
            cleanup_post_quantum_keys();
#endif
        }
    }

    return rc;
}

static int pkd_init_socket_wrapper(void) {
    int rc = 0;
    char *mkdtemp_str = NULL;

    if (pkd_dargs.opts.socket_wrapper.mkdtemp_str == NULL) {
        goto out;
    }

    mkdtemp_str = strdup(pkd_dargs.opts.socket_wrapper.mkdtemp_str);
    if (mkdtemp_str == NULL) {
        fprintf(stderr, "pkd_init_socket_wrapper strdup failed\n");
        goto errstrdup;
    }
    pkd_dargs.opts.socket_wrapper.mkdtemp_str = mkdtemp_str;

    if (mkdtemp(mkdtemp_str) == NULL) {
        fprintf(stderr, "pkd_init_socket_wrapper mkdtemp '%s' failed\n", mkdtemp_str);
        goto errmkdtemp;
    }

    if (setenv("SOCKET_WRAPPER_DIR", mkdtemp_str, 1) != 0) {
        fprintf(stderr, "pkd_init_socket_wrapper setenv failed\n");
        goto errsetenv;
    }

    goto out;
errsetenv:
errmkdtemp:
    free(mkdtemp_str);
errstrdup:
    rc = -1;
out:
    return rc;
}

static int pkd_rmfiles(const char *path) {
    char bin[1024] = { 0 };
    snprintf(&bin[0], sizeof(bin), "rm -f %s/*", path);
    return system_checked(bin);
}

static int pkd_cleanup_socket_wrapper(void) {
    int rc = 0;

    if (pkd_dargs.opts.socket_wrapper.mkdtemp_str == NULL) {
        goto out;
    }

    /* clean up socket-wrapper unix domain sockets */
    if (pkd_rmfiles(pkd_dargs.opts.socket_wrapper.mkdtemp_str) != 0) {
        fprintf(stderr, "pkd_cleanup_socket_wrapper pkd_rmfiles '%s' failed\n",
                        pkd_dargs.opts.socket_wrapper.mkdtemp_str);
        goto errrmfiles;
    }

    if (rmdir(pkd_dargs.opts.socket_wrapper.mkdtemp_str) != 0) {
        fprintf(stderr, "pkd_cleanup_socket_wrapper rmdir '%s' failed\n",
                        pkd_dargs.opts.socket_wrapper.mkdtemp_str);
        goto errrmdir;
    }

    free(pkd_dargs.opts.socket_wrapper.mkdtemp_str);

    goto out;
errrmdir:
errrmfiles:
    rc = -1;
out:
    return rc;
}

int main(int argc, char **argv) {
    int i = 0;
    int rc = 0;
    int exit_code = -1;

    unsetenv("SSH_AUTH_SOCK");

    pkd_dargs.payload.buf = default_payload_buf;
    pkd_dargs.payload.len = default_payload_len;

    rc = ssh_init();
    if (rc != 0) {
        goto out;
    }

#ifdef HAVE_ARGP_H
    argp_parse(&parser, argc, argv, 0, 0, NULL);
#else /* HAVE_ARGP_H */
    (void) argc;  (void) argv;
#endif /* HAVE_ARGP_H */

    rc = pkd_init_socket_wrapper();
    if (rc != 0) {
        fprintf(stderr, "pkd_init_socket_wrapper failed: %d\n", rc);
        goto out_finalize;
    }

    if (pkd_dargs.opts.list != 0) {
        while (testmap[i].testname != NULL) {
            printf("%s\n", testmap[i++].testname);
        }
    } else {
        exit_code = pkd_run_tests();
        if (exit_code != 0) {
            fprintf(stderr, "pkd_run_tests failed: %d\n", exit_code);
        }
    }

    rc = pkd_cleanup_socket_wrapper();
    if (rc != 0) {
        fprintf(stderr, "pkd_cleanup_socket_wrapper failed: %d\n", rc);
    }

out_finalize:
    rc = ssh_finalize();
    if (rc != 0) {
        fprintf(stderr, "ssh_finalize: %d\n", rc);
    }
out:
    return exit_code;
}///// OQS_TEMPLATE_FRAGMENT_EMIT_KEYTESTS_START
