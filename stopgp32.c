/* Copyright © 2018 Jakub Wilk <jwilk@jwilk.net>
 * SPDX-License-Identifier: MIT
 */

#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define PROGRAM_NAME "stopgp32"
#define DEFAULT_USER "<user@example.org>"

static const int rsa_bits = 1024;
static const uint32_t ts_min = 1136073600; /* 2006-01-01 */
static const uint32_t ts_max = 1514764800; /* 2018-01-01 */

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

#if OPENSSL_VERSION_NUMBER < 0x10100000
static void RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = rsa->n;
    if (e != NULL)
        *e = rsa->e;
    if (d != NULL)
        *d = rsa->d;
}
#endif

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

static void fprintsh(FILE *fp, const char *s)
{
    bool escape = true;
    for (const char *p = s; *p; p++) {
        char c = *p;
        if (c >= 'a' && c <= 'z')
            escape = false;
        else if (c >= 'A' && c <= 'Z')
            escape = false;
        else if (c >= '0' && c <= '9')
            escape = false;
        else if (c == '/' || c == '.' || c == ',' || c == '+' || c == '-' || c == '_')
            escape = false;
        else {
            escape = true;
            break;
        }
    }
    if (!escape) {
        fprintf(fp, "%s", s);
        return;
    }
    fprintf(fp, "'");
    for (const char *p = s; *p; p++)
        if (*p == '\'')
            fprintf(fp, "'\\''");
        else
            putc(*p, fp);
    fprintf(fp, "'");
}

static void printsh(const char *s)
{
    fprintsh(stdout, s);
}

struct cache_dir
{
    char path[PATH_MAX];
    const char *home_path;
    DIR *handle;
    int fd;
};

static void cache_dir_init(struct cache_dir *o, const char *path, bool real)
{
    const char *home = getenv("HOME");
    const char *cache_home = getenv("XDG_CACHE_HOME");
    if (cache_home && cache_home[0] != '/')
        cache_home = NULL;
    o->home_path = NULL;
    if (path != NULL) {
        size_t size = strnlen(path, sizeof o->path);
        if (size >= sizeof o->path) {
            errno = ENAMETOOLONG;
            posix_error(path);
        }
        strcat(o->path, path);
    } else if (cache_home) {
        int size = snprintf(o->path, sizeof o->path, "%s/" PROGRAM_NAME, cache_home);
        if (size < 0)
            posix_error(NULL);
        if ((size_t) size >= sizeof o->path) {
            errno = ENAMETOOLONG;
            posix_error("$XDG_CACHE_HOME/" PROGRAM_NAME);
        }
    } else {
        if ((home == NULL) || (*home == '\0')) {
            errno = ENOTDIR;
            posix_error("$HOME");
        }
        int size = snprintf(o->path, sizeof o->path, "%s/.cache/" PROGRAM_NAME, home);
        if (size < 0)
            posix_error(NULL);
        if ((size_t) size >= sizeof o->path) {
            errno = ENAMETOOLONG;
            posix_error("$HOME/.cache/" PROGRAM_NAME);
        }
    }
    if ((home != NULL) && (*home != '\0')) {
        size_t home_len = strlen(home);
        if ((strncmp(o->path, home, home_len) == 0) && (o->path[home_len] == '/'))
            o->home_path = o->path + home_len + 1;
    }
    if (!real) {
        o->handle = NULL;
        o->fd = -1;
        return;
    }
    if (path == NULL) {
        char *p = strrchr(o->path, '/');
        assert(p != NULL);
        *p = '\0';
        int rc = mkdir(o->path, 0700);
        if (rc < 0 && errno != EEXIST)
            posix_error(o->path);
        *p = '/';
    }
    int rc = mkdir(o->path, 0700);
    if (rc < 0 && errno != EEXIST)
        posix_error(o->path);
    o->handle = opendir(o->path);
    if (o->handle == NULL)
        posix_error(o->path);
    o->fd = dirfd(o->handle);
    if (o->fd < 0)
        posix_error(o->path);
    rc = flock(o->fd, LOCK_EX | LOCK_NB);
    if (rc < 0)
        posix_error(o->path);
}

static void cache_dir_close(struct cache_dir *o)
{
    o->path[0] = '\0';
    o->home_path = NULL;
    if (o->handle != NULL) {
        int rc = closedir(o->handle);
        if (rc < 0)
            posix_error(o->path);
        o->handle = NULL;
        o->fd = -1;
    }
}

static void openssl_error()
{
    fprintf(stderr, "%s: ", PROGRAM_NAME);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static int genrsa_callback(int a, int b, BN_GENCB *cb)
{
    (void) a; (void) b; (void) cb;
    fprintf(stderr, ".");
    return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000
static BN_GENCB *BN_GENCB_new(void)
{
    BN_GENCB *cb = malloc(sizeof (BN_GENCB));
    if (cb == NULL)
        perror(NULL);
    return cb;
}

static void BN_GENCB_free(BN_GENCB *cb)
{
    free(cb);
}
#endif

static void get_rsa_name(RSA *rsa, char *name)
{
    static const char alphabet[] = "ybndrfg8ejkmcpqxot1uwisza345h769";
    unsigned char sha[SHA_DIGEST_LENGTH];
    struct openpgp_packet pkt;
    openpgp_from_rsa(&pkt, rsa);
    openpgp_set_timestamp(&pkt, 0);
    openpgp_fingerprint(&pkt, sha);
    uint64_t rsaid;
    memcpy(&rsaid, sha, sizeof rsaid);
    strcpy(name, "rsa-");
    for (int i = 0; i < 8; i++) {
        name[i + 4] = alphabet[rsaid % 32];
        rsaid /= 32;
    }
    strcpy(name + 12, ".pem");
}

static void retrieve_key(struct openpgp_packet *pkt, struct cache_dir *cache_dir, char *name)
{
    BIO *io = NULL;
    RSA *rsa = NULL;
    errno = 0;
    struct dirent *ent;
    while (true) {
        errno = 0;
        ent = readdir(cache_dir->handle);
        if (ent == NULL)
            break;
        size_t len = strlen(ent->d_name);
        if (len < 5)
            continue;
        if (strcmp(ent->d_name + (len - 4), ".pem") == 0)
            break;
        else
            continue;
    }
    if (ent) {
        strcpy(name, ent->d_name);
        fprintf(stderr, "%s: retrieving RSA key ", PROGRAM_NAME);
        fprintsh(stderr, name);
        fprintf(stderr, " from cache\n");
        int fd = openat(cache_dir->fd, name, O_RDONLY);
        if (fd < 0)
            posix_error(name);
        FILE *fp = fdopen(fd, "r");
        if (fp == NULL)
            posix_error(name);
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
    } else if (errno == 0) {
        fprintf(stderr, "%s: generating new RSA key: ", PROGRAM_NAME);
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
        get_rsa_name(rsa, name);
        fprintf(stderr, " ");
        fprintsh(stderr, name);
        fprintf(stderr, "\n");
        int fd = openat(cache_dir->fd, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            posix_error(name);
        FILE *fp = fdopen(fd, "w");
        if (fp == NULL)
            posix_error(name);
        io = BIO_new_fp(fp, BIO_CLOSE);
        if (io == NULL)
            openssl_error();
        if (!PEM_write_bio_RSAPrivateKey(io, rsa, NULL, NULL, 0, NULL, NULL))
            openssl_error();
    } else
        posix_error(cache_dir->path);
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

struct progress
{
    double time;
    uint64_t count;
};

static void progress_start(struct progress *obj)
{
    obj->time = xtime();
    obj->count = 0;
    fprintf(stderr, "%s: searching...", PROGRAM_NAME);
}

static void progress_update(struct progress *obj)
{
    double t0 = obj->time;
    double t = xtime();
    if (t > t0) {
        double v = obj->count / 1.0E6 / (t - t0);
        fprintf(stderr, "\r\033[1K%s: searching... %.2f Mkeys/s", PROGRAM_NAME, v);
    }
}

static void progress_stop(struct progress *obj)
{
    fprintf(stderr, "\r\033[1K%s: searching...", PROGRAM_NAME);
    double t0 = obj->time;
    double t = xtime();
    if (t > t0) {
        double v = obj->count / 1.0E6 / (t - t0);
        fprintf(stderr, " %.2f Mkeys/s", v);
    }
    fprintf(stderr, "\n");
}

static void show_usage(FILE *fp)
{
    fprintf(fp, "Usage: %s [-u USERID] [-p] [-d DIR] [-j N] KEYID [KEYID...]\n", PROGRAM_NAME);
    if (fp != stdout)
        return;
    char *cd_path = NULL;
    struct cache_dir cd;
    cache_dir_init(&cd, NULL, false);
    if (cd.home_path != NULL) {
        assert(cd.home_path >= cd.path + 2);
        cd_path = cd.path + (cd.home_path - cd.path) - 2;
        cd_path[0] = '~';
        cd_path[1] = '/';
    } else
        cd_path = cd.path;
    fprintf(fp,
        "\n"
        "Options:\n"
        "  -u USERID   add this user ID (default: " DEFAULT_USER ")\n"
        "  -p          only print pem2openpgp(1) commands; don't run them\n"
        "  -d DIR      cache RSA keys in DIR (default: %s)\n"
        "  -j N        use N threads (default: 1)\n"
        "  -j auto     use as many threads as possible\n"
        "  -h, --help  show this help message and exit\n",
        cd_path
    );
    cache_dir_close(&cd);
}

struct keyidlist
{
    size_t len;
    size_t count;
    uint32_t *keys;
    char *found;
};

static struct keyidlist kil_new(size_t len)
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

static void pem2openpgp_print(uint32_t keyid, uint32_t ts, const char *user, const struct cache_dir *cache_dir, const char *pem_name)
{
    printf("PEM2OPENPGP_TIMESTAMP=%" PRIu32 " pem2openpgp ", ts);
    printsh(user);
    printf(" < ");
    if (cache_dir->home_path) {
        printf("~/");
        printsh(cache_dir->home_path);
    } else
        printsh(cache_dir->path);
    printf("/");
    printsh(pem_name);
    printf(" > %08" PRIX32 ".pgp\n", keyid);
}

static void pem2openpgp_exec(uint32_t keyid, uint32_t ts, const char *user, const struct cache_dir *cache_dir, const char *pem_name)
{
    char * const argv[] = { "pem2openpgp", (char*) user, (char*) NULL };
    int in_fd = openat(cache_dir->fd, pem_name, O_RDONLY);
    if (in_fd < 0)
        posix_error(pem_name);
    char tmp_path[13], path[13];
    int size = sprintf(tmp_path, "%08" PRIX32 ".tmp", keyid);
    if (size < 0)
        posix_error(NULL);
    size = sprintf(path, "%08" PRIX32 ".pgp", keyid);
    if (size < 0)
        posix_error(NULL);
    int out_fd = open(tmp_path, O_WRONLY | O_TRUNC | O_CREAT, 0600);
    if (out_fd < 0)
        posix_error(path);
    pid_t pid = fork();
    if (pid < 0)
        posix_error("fork()");
    if (pid == 0) {
        /* child: */
        int fd = dup2(in_fd, STDIN_FILENO);
        if (fd < 0)
            posix_error("dup2()");
        close(in_fd);
        fd = dup2(out_fd, STDOUT_FILENO);
        if (fd < 0)
            posix_error("dup2()");
        close(out_fd);
        char ts_str[11];
        size = sprintf(ts_str, "%" PRIu32, ts);
        if (size < 0)
            posix_error(NULL);
        int rc = setenv("PEM2OPENPGP_TIMESTAMP", ts_str, true);
        if (rc < 0)
            posix_error("setenv()");
        execvp(argv[0], argv);
        abort();
    }
    /* parent: */
    int rc = close(in_fd);
    if (rc < 0)
        posix_error("close()");
    rc = close(out_fd);
    if (rc < 0)
        posix_error("close()");
    int wstatus;
    pid = wait(&wstatus);
    if (pid < 0)
        posix_error("wait()");
    if (WIFEXITED(wstatus) && (WEXITSTATUS(wstatus) == 0))
        rename(tmp_path, path);
    else {
        fprintf(stderr, "%s: %s(1) failed\n", PROGRAM_NAME, argv[0]);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    const char *user = DEFAULT_USER;
    const char *cache_path = NULL;
    int num_threads = 1;
    bool only_print = false;
    int opt;
    while ((opt = getopt(argc, argv, "upd:j:h-:")) != -1)
        switch (opt) {
        case 'u':
            user = optarg;
            break;
        case 'p':
            only_print = true;
            break;
        case 'd':
            cache_path = optarg;
            break;
        case 'j':
            if (strcmp(optarg, "auto") == 0)
                num_threads = -1;
            else {
                char *endarg;
                long int l = strtol(optarg, &endarg, 10);
                if (*endarg != '\0') {
                    errno = EINVAL;
                    posix_error("-j");
                }
                if (l <= 0 || l >= INT_MAX) {
                    errno = ERANGE;
                    posix_error("-j");
                }
                num_threads = (int) l;
            }
            break;
        case 'h':
            show_usage(stdout);
            exit(EXIT_SUCCESS);
            break;
        case '-':
            if (strcmp(optarg, "help") == 0) {
                show_usage(stdout);
                exit(EXIT_SUCCESS);
            }
            /* fall through */
        default:
            show_usage(stderr);
            exit(EXIT_FAILURE);
        }
    if (optind >= argc) {
        show_usage(stderr);
        exit(EXIT_FAILURE);
    }
    argc -= optind;
    argv += optind;
#ifdef _OPENMP
    if (num_threads >= 1)
        omp_set_num_threads(num_threads);
#else
    if (num_threads != 1) {
        errno = ENOSYS;
        posix_error("-j");
    }
#endif
    struct keyidlist keyidlist = kil_new(argc);
    for (size_t i = 0; i < keyidlist.len; i++) {
        const char *arg = argv[i];
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
    struct cache_dir cache_dir;
    cache_dir_init(&cache_dir, cache_path, true);
    struct openpgp_packet pkt;
    while (true) {
        char pem_name[NAME_MAX + 1];
        retrieve_key(&pkt, &cache_dir, pem_name);
        struct progress progress;
        progress_start(&progress);
        #pragma omp parallel for firstprivate(pkt)
        for (uint32_t ts = ts_min; ts < ts_max; ts++) {
            #pragma omp atomic
            progress.count++;
            unsigned char sha[SHA_DIGEST_LENGTH];
            openpgp_set_timestamp(&pkt, ts);
            openpgp_fingerprint(&pkt, sha);
            uint32_t keyid;
            memcpy(&keyid, sha + SHA_DIGEST_LENGTH - sizeof keyid, sizeof keyid);
            keyid = ntohl(keyid);
            if (kil_crude_check(&keyidlist, keyid))
                #pragma omp critical
                if (kil_pop(&keyidlist, keyid)) {
                    progress_stop(&progress);
                    if (only_print)
                        pem2openpgp_print(keyid, ts, user, &cache_dir, pem_name);
                    else {
                        fprintf(stderr, "%s: found %08" PRIX32 "\n", PROGRAM_NAME, keyid);
                        pem2openpgp_exec(keyid, ts, user, &cache_dir, pem_name);
                    }
                    if (keyidlist.count == 0) {
                        cache_dir_close(&cache_dir);
                        kil_free(&keyidlist);
                        exit(EXIT_SUCCESS);
                    }
                    progress_start(&progress);
                }
            if ((ts & 0xFFFFF) == 0)
                #pragma omp critical
                progress_update(&progress);
        }
        progress_stop(&progress);
    }
    abort(); /* unreachable */
}

/* vim:set ts=4 sw=4 sts=4 et:*/
