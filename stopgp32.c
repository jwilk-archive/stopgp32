/* Copyright © 2018 Jakub Wilk <jwilk@jwilk.net>
 * SPDX-License-Identifier: MIT
 */

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define PROGRAM_NAME "stopgp32"

const int rsa_bits = 1024;
const uint32_t ts_min = 1136073600; /* 2006-01-01 */
const uint32_t ts_max = 1514764800; /* 2018-01-01 */

static size_t bignum2mpi(const BIGNUM *n, unsigned char *to)
{
    int nbits = BN_num_bits(n);
    assert(nbits <= 0xFFFF);
    to[0] = nbits >> 8;
    to[1] = nbits & 0xFF;
    size_t size = 2 + BN_bn2bin(n, to + 2);
    return size;
}

struct openpgp_packet
{
    unsigned char data[0x10000];
};

static void openpgp_from_rsa(struct openpgp_packet *pkt, const RSA *rsa)
{
    unsigned char *data = pkt->data;
    data[0] = 0x99;
    data[3] = 0x04;
    data[8] = 0x01;
    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);
    size_t size = 9;
    size += bignum2mpi(n, data + size);
    size += bignum2mpi(e, data + size);
    assert(size <= 0xFFFF);
    uint16_t len = htons(size - 3);
    memcpy(data + 1, &len, sizeof len);
}

static void openpgp_set_timestamp(struct openpgp_packet *pkt, uint32_t timestamp)
{
    timestamp = htonl(timestamp);
    memcpy(pkt->data + 4, &timestamp, sizeof timestamp);
}

static void openpgp_fingerprint(const struct openpgp_packet *pkt, unsigned char *sha)
{
    size_t size = 3 + (pkt->data[1] << 8) + pkt->data[2];
    SHA1(pkt->data, size, sha);
}

static void posix_error(const char *context)
{
    int orig_errno = errno;
    fprintf(stderr, "%s: ", PROGRAM_NAME);
    errno = orig_errno;
    perror(context);
    exit(EXIT_FAILURE);
}

static int get_cache_dir(void)
{
    char path[PATH_MAX];
    const char *cache_home = getenv("XDG_CACHE_HOME");
    if (cache_home && cache_home[0] != '/')
        cache_home = NULL;
    if (cache_home) {
        size_t len = strlen(cache_home);
        if (len >= SIZE_MAX) {
            errno = ENAMETOOLONG;
            posix_error("$XDG_CACHE_HOME");
        }
        strcpy(path, cache_home);
    } else {
        char *home = getenv("HOME");
        if (!home) {
            errno = ENOTDIR;
            posix_error("$HOME");
        }
        int size = snprintf(path, sizeof path, "%s/.cache", home);
        if (size >= sizeof path) {
            errno = ENAMETOOLONG;
            size = -1;
        }
        if (size < 0)
            posix_error("$HOME/.cache");
    }
    int rc = mkdir(path, 0700);
    if (rc < 0 && errno != EEXIST)
        posix_error(path);
    int cache_home_fd = open(path, O_RDONLY | O_DIRECTORY);
    if (cache_home_fd < 0)
        posix_error(path);
    rc = mkdirat(cache_home_fd, PROGRAM_NAME, 0700);
    if (rc < 0 && errno != EEXIST)
        posix_error(path);
    int fd = openat(cache_home_fd, PROGRAM_NAME,  O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        posix_error("$XDG_CACHE_HOME/" PROGRAM_NAME);
    rc = close(cache_home_fd);
    if (rc < 0)
        posix_error("close()");
    rc = flock(fd, LOCK_EX | LOCK_NB);
    if (rc < 0)
        posix_error("$XDG_CACHE_HOME/" PROGRAM_NAME);
    return fd;
}

static void openssl_error()
{
    fprintf(stderr, "%s: ", PROGRAM_NAME);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static int genrsa_callback(int a, int b, BN_GENCB *cb)
{
    fprintf(stderr, ".");
    return 1;
}

static void make_pem_name(char *name, int n)
{
    int size = snprintf(name, NAME_MAX, "rsa%04d.pem", n);
    if (size >= NAME_MAX) {
        size = -1;
        errno = ENAMETOOLONG;
    }
    if (size < 0)
        posix_error(NULL);
}

static void retrieve_key(struct openpgp_packet *pkt, int dirfd, int n)
{
    BIO *io = NULL;
    RSA *rsa = NULL;
    char name[NAME_MAX];
    make_pem_name(name, n);
    int fd = openat(dirfd, name, O_RDONLY, 0600);
    if (fd >= 0) {
        fprintf(stderr, "%s: key #%d: retrieving from cache\n", PROGRAM_NAME, n);
        FILE *fp = fdopen(fd, "r");
        io = BIO_new_fp(fp, BIO_CLOSE);
        if (io == NULL)
            openssl_error();
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(io, NULL, NULL, NULL);
        if (pkey == NULL)
            openssl_error();
        rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa == NULL)
            openssl_error();
        EVP_PKEY_free(pkey);
    } else if (errno == ENOENT) {
        fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            posix_error(name);
        FILE *fp = fdopen(fd, "w");
        if (fp == NULL)
            posix_error(name);
        io = BIO_new_fp(fp, BIO_CLOSE);
        if (io == NULL)
            openssl_error();
        fprintf(stderr, "%s: key #%d: generating new RSA key: ", PROGRAM_NAME, n);
        rsa = RSA_new();
        if (rsa == NULL)
            openssl_error();
        BIGNUM *exp = BN_new();
        if (exp == NULL)
            openssl_error();
        if (!BN_set_word(exp, 0x10001))
            openssl_error();
        BN_GENCB *cb = BN_GENCB_new();
        if (cb == NULL)
            openssl_error();
        BN_GENCB_set(cb, genrsa_callback, NULL);
        if (!RSA_generate_key_ex(rsa, rsa_bits, exp, cb))
            openssl_error();
        BN_GENCB_free(cb);
        BN_free(exp);
        fprintf(stderr, "\n");
        if (!PEM_write_bio_RSAPrivateKey(io, rsa, NULL, NULL, 0, NULL, NULL))
            openssl_error();
    } else
        posix_error(name);
    assert(rsa != NULL);
    openpgp_from_rsa(pkt, rsa);
    RSA_free(rsa);
    BIO_free_all(io);
}

static double xtime()
{
    struct timespec ts;
    int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (rc < 0)
        posix_error("clock_gettime()");
    return ts.tv_sec + ts.tv_nsec * 1E-9;
}

static void show_usage(FILE *fp)
{
    fprintf(fp, "Usage: %s KEY [KEY...]\n", PROGRAM_NAME);
}

struct keyidlist
{
    size_t len;
    size_t count;
    uint32_t *keys;
    char *found;
};

struct keyidlist kil_new(size_t len)
{
    struct keyidlist obj;
    obj.len = obj.count = len;
    obj.keys = calloc(len, sizeof (uint32_t));
    if (obj.keys == NULL)
        posix_error(NULL);
    obj.found = calloc(len, 1);
    if (obj.found == NULL)
        posix_error(NULL);
    return obj;
}

static bool kil_crude_check(const struct keyidlist *obj, uint32_t keyid)
{
    for (size_t i = 0; i < obj->len; i++)
        if (obj->keys[i] == keyid)
            return true;
    return false;
}

static bool kil_pop(struct keyidlist *obj, uint32_t keyid)
{
    for (size_t i = 0; i < obj->len; i++)
        if (obj->keys[i] == keyid && obj->found[i] == 0) {
            obj->found[i] = 1;
            obj->count--;
            return true;
        }
    return false;
}

static void kil_free(struct keyidlist *obj)
{
    obj->len = obj->count = 0;
    free(obj->keys);
    obj->keys = NULL;
    free(obj->found);
    obj->found = NULL;
}

int main(int argc, char **argv)
{
    if (argc <= 1) {
        show_usage(stderr);
        exit(EXIT_FAILURE);
    }
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        show_usage(stdout);
        exit(EXIT_SUCCESS);
    }
    struct keyidlist keyidlist = kil_new(argc - 1);
    for (size_t i = 0; i < keyidlist.len; i++) {
        const char *arg = argv[i + 1];
        for (size_t j = 0; j < 8; j++) {
            uint32_t d = arg[j];
            if (d >= '0' && d <= '9') {
                d -= '0';
            } else if (d >= 'a' && d <= 'f') {
                d -= 'a' - 10;
            } else if (d >= 'A' && d <= 'F') {
                d -= 'A' - 10;
            } else if (d == '\0') {
                fprintf(stderr, "%s: key ID too short: %s\n", PROGRAM_NAME, arg);
                exit(EXIT_FAILURE);
            } else {
                fprintf(stderr, "%s: bad key ID: %s\n", PROGRAM_NAME, arg);
                exit(EXIT_FAILURE);
            }
            keyidlist.keys[i] |= d << ((7 - j) * 4);
        }
        if (arg[8] != '\0') {
            fprintf(stderr, "%s: key ID too long: %s\n", PROGRAM_NAME, arg);
            exit(EXIT_FAILURE);
        }
    }
    int cache_fd = get_cache_dir();
    struct openpgp_packet pkt;
    uint64_t c = 0;
    double rt0 = xtime();
    bool fresh_line = true;
    for (int rsano = 1;; rsano++) {
        retrieve_key(&pkt, cache_fd, rsano);
        #pragma omp parallel for firstprivate(pkt)
        for (uint32_t ts = ts_min; ts < ts_max; ts++) {
            #pragma omp atomic
            c++;
            unsigned char sha[SHA_DIGEST_LENGTH];
            openpgp_set_timestamp(&pkt, ts);
            openpgp_fingerprint(&pkt, sha);
            uint32_t keyid;
            memcpy(&keyid, sha + SHA_DIGEST_LENGTH - sizeof keyid, sizeof keyid);
            keyid = ntohl(keyid);
            if (kil_crude_check(&keyidlist, keyid))
                #pragma omp critical
                if (kil_pop(&keyidlist, keyid)) {
                    if (!fresh_line) {
                        fprintf(stderr, "\n");
                        fresh_line = true;
                    }
                    char pem_name[NAME_MAX];
                    make_pem_name(pem_name, rsano);
                    printf("PEM2OPENPGP_TIMESTAMP=%" PRIu32 " pem2openpgp '<user@example.org>' < %s > %08" PRIX32 ".pgp\n", ts, pem_name, keyid);
                    if (keyidlist.count == 0)
                        exit(EXIT_SUCCESS);
                }
            if ((ts & 0xFFFF) == 0)
            #pragma omp critical
            {
                double rt = xtime();
                if (rt > rt0) {
                    fprintf(stderr, "\r\033[1K%s: searching... %.2f Mkeys/s", PROGRAM_NAME, c / 1.0E6 / (rt - rt0));
                    fresh_line = false;
                }
                if (rt > rt0 - 10) {
                    rt0 = rt;
                    c = 0;
                }
            }
        }
        if (!fresh_line) {
            fprintf(stderr, "\n");
            fresh_line = true;
        }
    }
    close(cache_fd);
    kil_free(&keyidlist);
    exit(EXIT_FAILURE);
}

/* vim:set ts=4 sw=4 sts=4 et:*/
