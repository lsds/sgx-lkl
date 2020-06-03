#include <vic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../libvicsetup/hexdump.h"
#include "../libvicsetup/verity.h"
#include "../libvicsetup/crypto.h"
#include "../libvicsetup/lukscommon.h"
#include "../libvicsetup/include/libcryptsetup.h"
#include "../libvicsetup/trace.h"

#define USAGE \
    "\n" \
    "Usage: %s <action> ...\n" \
    "\n" \
    "actions:\n" \
    "    luksDump\n" \
    "    luksFormat\n" \
    "    luksGetMasterKey\n" \
    "    luksAddKey\n" \
    "    luksChangeKey\n" \
    "    luksRemoveKey\n" \
    "    luksOpen\n" \
    "    luksOpenByKey\n" \
    "    luksClose\n" \
    "    verityDump\n" \
    "    verityFormat\n" \
    "    verityOpen\n" \
    "    cryptsetupLuksFormat\n" \
    "    veritysetupOpen\n" \
    "\n"

static const char* arg0;

void vic_hexdump(const void* data, size_t size);

void vic_hexdump_indent(const void* data, size_t size, size_t indent);

__attribute__((format(printf, 1, 2)))
static void err(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", arg0);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    exit(1);
}

int get_opt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    size_t olen = strlen(opt);

    if (optarg)
        *optarg = NULL;

    if (!opt)
        err("unexpected");


    for (int i = 0; i < *argc; )
    {
        if (strcmp(argv[i], opt) == 0)
        {
            if (optarg)
            {
                if (i + 1 == *argc)
                    err("%s: missing option argument", opt);

                *optarg = argv[i+1];
                memmove(&argv[i], &argv[i+2], (*argc - i - 1) * sizeof(char*));
                (*argc) -= 2;
                return 0;
            }
            else
            {
                memmove(&argv[i], &argv[i+1], (*argc - i) * sizeof(char*));
                (*argc)--;
                return 0;
            }
        }
        else if (strncmp(argv[i], opt, olen) == 0 && argv[i][olen] == '=')
        {
            if (!optarg)
                err("%s: extraneous '='", opt);

            *optarg = &argv[i][olen + 1];
            memmove(&argv[i], &argv[i+1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return 0;
        }
        else
        {
            i++;
        }
    }

    /* Not found! */
    return -1;
}

int get_opt_u64(
    int* argc,
    const char* argv[],
    const char* opt,
    uint64_t* optarg)
{
    const char* str;
    uint64_t x;
    char* end = NULL;

    if (get_opt(argc, argv, opt, &str) != 0 || !str)
        return -1;

    x = strtoul(str, &end, 0);

    if (!end || *end)
        err("%s: bad option argument", opt);

    *optarg = x;
    return 0;
}

void dump_args(int argc, const char* argv[])
{
    for (int i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);
}

static int luksDump(int argc, const char* argv[])
{
    vic_blockdev_t* dev;
    vic_result_t r;
    bool dump_payload = false;
    const int data_flags = VIC_RDONLY;

    /* Get --dump-payload option */
    if (get_opt(&argc, argv, "--dump-payload", NULL) == 0)
        dump_payload = true;

    if (argc != 3)
    {
        fprintf(stderr,
            "Usage: %s %s <luksfile>\n"
            "OPTIONS:\n"
            "    --dump-payload\n"
            "\n",
            argv[0], argv[1]);
        exit(1);
    }

    if (vic_blockdev_open(argv[2], data_flags, 0, &dev) != VIC_OK)
        err("cannot open %s\n", argv[2]);

    if ((r = vic_luks_dump(dev)) != VIC_OK)
        err("%s() failed: %s\n", argv[1], vic_result_string(r));

    /* dump the payload */
    if (dump_payload)
    {
        vic_luks_stat_t buf;
        size_t blkno;
        size_t num_blocks;
        FILE* os;

        if (vic_luks_stat(dev, &buf) != VIC_OK)
            err("vic_luks_stat() failed: %s\n", argv[2]);

        printf("payload\n");
        printf("{\n");
        printf("  payload_offset: %zu\n", buf.payload_offset);
        printf("  payload_size: %zu\n", buf.payload_size);
        printf("  payload_data:\n");

        blkno = buf.payload_offset / VIC_SECTOR_SIZE;
        num_blocks = buf.payload_size / VIC_SECTOR_SIZE;

        if (!(os = fopen("/tmp/integrt", "wb")))
            err("failed to open /tmp/integrt");

        for (size_t i = blkno; i < blkno + num_blocks; i++)
        {
            uint8_t blk[VIC_SECTOR_SIZE];
            const size_t indent = 2;

            if (vic_blockdev_get(dev, i, blk, 1) != 0)
                err("failed to read block %zu\n", i);

            printf("    [BLOCK %zu]\n", i);
            vic_hexdump_special(&blk, sizeof(blk), true, true, indent);

            if (fwrite(&blk, 1, sizeof(blk), os) != sizeof(blk))
                err("failed to write /tmp/integrt");
        }

        fclose(os);

        printf("}\n");
    }

    vic_blockdev_close(dev);

    return 0;
}

static int luksFormat(int argc, const char* argv[])
{
    vic_blockdev_t* dev;
    vic_luks_version_t version = LUKS_VERSION_1;
    const char* cipher = NULL;
    const char* keyslot_cipher = NULL;
    const char* uuid = NULL;
    const char* hash = NULL;
    const char* keyfile = NULL;
    const vic_key_t* key = NULL;
    vic_key_t key_buf;
    size_t key_size = 0;
    vic_result_t r;
    const char* integrity = NULL;
    uint64_t mk_iterations = 0;
    uint64_t slot_iterations = 0;
    uint64_t pbkdf_memory = 0;

    /* Get --luks1 option */
    if (get_opt(&argc, argv, "--luks1", NULL) == 0)
        version = LUKS_VERSION_1;

    /* Get --luks2 option */
    if (get_opt(&argc, argv, "--luks2", NULL) == 0)
        version = LUKS_VERSION_2;

    /* Get --cipher option */
    get_opt(&argc, argv, "--cipher", &cipher);

    /* Get --keyslot-cipher option */
    get_opt(&argc, argv, "--keyslot-cipher", &keyslot_cipher);

    /* Get --uuid option */
    get_opt(&argc, argv, "--uuid", &uuid);

    /* Get --hash option */
    get_opt(&argc, argv, "--hash", &hash);

    if (!hash)
        hash = "sha256";

    /* Get --keyfile option */
    {
        get_opt(&argc, argv, "--keyfile", &keyfile);

        if (keyfile)
        {
            if (vic_luks_load_key(keyfile, &key_buf, &key_size) != VIC_OK)
                err("failed to load keyfile: %s", keyfile);

            key = &key_buf;
        }
    }

    /* Get --integrity option */
    get_opt(&argc, argv, "--integrity", &integrity);

    /* Get --mk-iterations option */
    get_opt_u64(&argc, argv, "--mk-iterations", &mk_iterations);

    /* Get --slot-iterations option */
    get_opt_u64(&argc, argv, "--slot-iterations", &slot_iterations);

    /* Get --pbkdf-memory option */
    get_opt_u64(&argc, argv, "--pbkdf-memory", &pbkdf_memory);

    /* Check usage */
    if (argc != 4)
    {
        fprintf(stderr,
            "Usage: %s %s [OPTIONS] <luksfile> <pwd>\n"
            "OPTIONS:\n"
            "    --luks1\n"
            "    --luks2\n"
            "    --cipher <cipher>\n"
            "    --keyslot-cipher <cipher>\n"
            "    --uuid <uuid>\n"
            "    --hash <type>\n"
            "    --keyfile <keyfile>\n"
            "    --integrity <type>\n"
            "    --mk-iterations <count>\n"
            "    --slot-iterations <count>\n"
            "    --pbkdf-memory <count>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* luksfile = argv[2];
    const char* pwd = argv[3];

    if (vic_blockdev_open(luksfile, VIC_RDWR, 0, &dev) != VIC_OK)
        err("cannot open %s\n", luksfile);

    if (!keyslot_cipher)
        keyslot_cipher = LUKS_DEFAULT_CIPHER;

    /* Randomly generate a new key */
    if (!key)
    {
        key = &key_buf;
        vic_random(&key_buf, sizeof(key_buf));
        key_size = sizeof(key_buf);
    }

    if ((r = vic_luks_format(
        dev,
        version,
        cipher,
        uuid,
        hash,
        mk_iterations,
        key,
        key_size,
        integrity)) != VIC_OK)
    {
        err("%s() failed: %s\n", argv[1], vic_result_string(r));
    }

    vic_kdf_t kdf =
    {
        .iterations = slot_iterations,
        .memory = pbkdf_memory,
    };

    if ((r = vic_luks_add_key_by_master_key(
        dev,
        keyslot_cipher,
        "pbkdf2",
        &kdf,
        key,
        key_size,
        pwd,
        strlen(pwd))) != VIC_OK)
    {
        err("%s() failed: %s\n", argv[1], vic_result_string(r));
    }

    vic_blockdev_close(dev);

    return 0;
}

static int cryptsetupLuksFormat(int argc, const char* argv[])
{
    struct crypt_device* cd;
    const char* type = NULL;
    const char* cipher = NULL;
    const char* cipher_mode = NULL;
    const char* keyslot_cipher = NULL;
    const char* uuid = NULL;
    const char* hash = NULL;
    const char* keyfile = NULL;
    vic_key_t key_buf;
    const vic_key_t* key = NULL;
    size_t key_size = 0;
    const char* integrity = NULL;
    uint64_t mk_iterations = 0;
    uint64_t slot_iterations = 0;
    const char* pbkdf_type = NULL;
    uint64_t pbkdf_memory = 0;
    uint64_t pbkdf_parallel = 0;
    uint64_t iter_time = 0;
    int r;

    /* Get --luks1 option */
    if (get_opt(&argc, argv, "--luks1", NULL) == 0)
        type = CRYPT_LUKS1;

    /* Get --luks2 option */
    if (get_opt(&argc, argv, "--luks2", NULL) == 0)
        type = CRYPT_LUKS2;

    /* Get --cipher option */
    get_opt(&argc, argv, "--cipher", &cipher);

    /* Get --cipher-mode option */
    get_opt(&argc, argv, "--cipher-mode", &cipher_mode);

    /* Get --pbkdf option */
    get_opt(&argc, argv, "--pbkdf", &pbkdf_type);

    /* Get --keyslot-cipher option */
    get_opt(&argc, argv, "--keyslot-cipher", &keyslot_cipher);

    /* Get --uuid option */
    get_opt(&argc, argv, "--uuid", &uuid);

    /* Get --hash option */
    get_opt(&argc, argv, "--hash", &hash);

    /* Get --keyfile option */
    {
        get_opt(&argc, argv, "--keyfile", &keyfile);

        if (keyfile)
        {
            if (vic_luks_load_key(keyfile, &key_buf, &key_size) != VIC_OK)
                err("failed to load keyfile: %s", keyfile);

            key = &key_buf;
        }
    }

    /* Get --integrity option */
    get_opt(&argc, argv, "--integrity", &integrity);

    /* Get --mk-iterations option */
    get_opt_u64(&argc, argv, "--mk-iterations", &mk_iterations);

    /* Get --slot-iterations option */
    get_opt_u64(&argc, argv, "--slot-iterations", &slot_iterations);

    /* Get --pbkdf-memory option */
    get_opt_u64(&argc, argv, "--pbkdf-memory", &pbkdf_memory);

    /* Get --pbkdf-parallel option */
    get_opt_u64(&argc, argv, "--pbkdf-parallel", &pbkdf_parallel);

    /* Get --iter-time option */
    get_opt_u64(&argc, argv, "--iter-time", &iter_time);

    /* Check usage */
    if (argc != 4)
    {
        fprintf(stderr,
            "Usage: %s %s [OPTIONS] <luksfile> <pwd>\n"
            "OPTIONS:\n"
            "    --luks1\n"
            "    --luks2\n"
            "    --cipher <cipher>\n"
            "    --keyslot-cipher <cipher>\n"
            "    --uuid <uuid>\n"
            "    --hash <type>\n"
            "    --keyfile <keyfile>\n"
            "    --integrity <type>\n"
            "    --mk-iterations <count>\n"
            "    --slot-iterations <count>\n"
            "    --pbkdf <type>\n"
            "    --pbkdf-memory <count>\n"
            "    --pbkdf-parallel <count>\n"
            "    --iter-time <milliseconds>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* luksfile = argv[2];
    const char* pwd = argv[3];

    if (crypt_init(&cd, luksfile) != 0)
        err("crypt_init() failed: %s\n", luksfile);

    if (!keyslot_cipher)
        keyslot_cipher = LUKS_DEFAULT_CIPHER;

#if 0
    if (!key)
    {
        key = &key_buf;
        vic_random(&key_buf, sizeof(key_buf));
        key_size = sizeof(key_buf);
    }
#endif

    if (!type || strcmp(type, CRYPT_LUKS1) == 0)
    {
        struct crypt_params_luks1 params =
        {
            .hash = "sha256",
        };

        if (hash)
            params.hash = hash;

        if ((r = crypt_format(
            cd,
            CRYPT_LUKS1,
            cipher,
            cipher_mode,
            NULL,
            (const char*)key,
            key_size,
            &params)) != 0)
        {
            err("crypt_format() failed: %d %s\n", r, strerror(r));
        }

        if ((r = crypt_keyslot_add_by_key(
            cd,
            CRYPT_ANY_SLOT,
            NULL, /* volume_key */
            0, /* volume_key_size */
            pwd,
            strlen(pwd),
            0)) != 0) /* flags */
        {
            err("crypt_keyslot_add_by_key() failed: %d %s\n", r, strerror(r));
        }
    }
    else if (strcmp(type, CRYPT_LUKS2) == 0)
    {
        struct crypt_pbkdf_type pbkdf =
        {
            .type = pbkdf_type,
            .hash = hash,
            .iterations = slot_iterations,
            .time_ms = iter_time,
            .max_memory_kb = pbkdf_memory,
            .parallel_threads = pbkdf_parallel,
            .flags = CRYPT_PBKDF_NO_BENCHMARK
        };
        struct crypt_params_luks2 params =
        {
            .sector_size = VIC_SECTOR_SIZE,
            .pbkdf = &pbkdf,
            .integrity = integrity
        };

        if ((r = crypt_format(
            cd,
            CRYPT_LUKS2,
            cipher,
            cipher_mode,
            NULL, /* uuid */
            (const char*)key, /* volume_key */
            key_size, /* volume_key_size */
            &params)) != 0)
        {
            err("crypt_format() failed: %d %s\n", r, strerror(r));
        }

        if ((r = crypt_keyslot_add_by_key(
            cd,
            CRYPT_ANY_SLOT,
            NULL, /* volume_key */
            0, /* volume_key_size */
            pwd,
            strlen(pwd),
            0)) != 0) /* flags */
        {
            err("crypt_keyslot_add_by_key() failed: %d %s\n", r, strerror(r));
        }
    }

    crypt_free(cd);

    return 0;
}

static int veritysetupOpen(int argc, const char* argv[])
{
    struct crypt_device* cd;
    uint8_t* root_hash;
    size_t root_hash_size;
    size_t data_size = 0;
    size_t hash_area_offset = 0;

    /* Get --data-size option */
    get_opt_u64(&argc, argv, "--data-size", &data_size);

    /* Get --hash-area-offset */
    get_opt_u64(&argc, argv, "--hash-area-offset", &hash_area_offset);

    /* Check usage */
    if (argc != 6)
    {
        fprintf(stderr,
            "Usage: %s %s <datafile> <name> <hashfile> <root_hash>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* datafile_opt = argv[2];
    const char* name_opt = argv[3];
    const char* hashfile_opt = argv[4];
    const char* root_hash_opt = argv[5];

    if (crypt_init(&cd, datafile_opt) != 0)
        err("crypt_init() failed: %s", datafile_opt);

    struct crypt_params_verity params =
    {
        .data_device = datafile_opt,
        .hash_device = hashfile_opt,
        .data_size = data_size / 4096,
        .hash_area_offset = hash_area_offset,
        .data_block_size = 4096,
        .hash_block_size = 4096,
    };

    if (crypt_load(cd, CRYPT_VERITY, &params) != 0)
        err("crypt_load() failed");

    if (vic_ascii_to_bin(root_hash_opt, &root_hash, &root_hash_size) != VIC_OK)
        err("bad root-hash argument");

    /* Verity the length of the root hash */
    {
        int n;

        if ((n = crypt_get_volume_key_size(cd)) != (int)root_hash_size)
            err("bad root hash size (must be %d bytes)", n);
    }

    if (crypt_activate_by_volume_key(
        cd,
        name_opt,
        (const char*)root_hash,
        root_hash_size,
        CRYPT_ACTIVATE_READONLY) != 0)
    {
        err("crypt_activate_by_volume_key() failed");
    }

    free(root_hash);
    crypt_free(cd);

    return 0;
}

static int luksGetMasterKey(int argc, const char* argv[])
{
    vic_blockdev_t* dev;
    vic_result_t r;
    vic_key_t key;
    size_t key_size;
    const int data_flags = VIC_RDONLY;

    /* Check usage */
    if (argc != 4)
    {
        fprintf(stderr,
            "Usage: %s %s <luksfile> <pwd>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* luksfile = argv[2];
    const char* pwd = argv[3];

    if (vic_blockdev_open(luksfile, data_flags, 0, &dev) != VIC_OK)
        err("cannot open %s\n", luksfile);

    if ((r = vic_luks_recover_master_key(
        dev,
        pwd,
        strlen(pwd),
        &key,
        &key_size)) != VIC_OK)
    {
        err("%s() failed: %s\n", argv[1], vic_result_string(r));
    }

    vic_hexdump(&key.buf, key_size);

    vic_blockdev_close(dev);

    return 0;
}

static int luksAddKey(int argc, const char* argv[])
{
    vic_blockdev_t* dev;
    vic_result_t r;
    const char* keyslot_cipher = NULL;
    const char* pbkdf = NULL;
    uint64_t slot_iterations = 0;
    uint64_t pbkdf_memory = 0;

    /* Get --pbkdf option */
    get_opt(&argc, argv, "--pbkdf", &pbkdf);

    /* Get --keyslot-cipher option */
    get_opt(&argc, argv, "--keyslot-cipher", &keyslot_cipher);

    /* Get --slot-iterations option */
    get_opt_u64(&argc, argv, "--slot-iterations", &slot_iterations);

    /* Get --pbkdf-memory option */
    get_opt_u64(&argc, argv, "--pbkdf-memory", &pbkdf_memory);

    /* Check usage */
    if (argc != 5)
    {
        fprintf(stderr,
            "Usage: %s %s <luksfile> <pwd> <new-pwd>\n"
            "OPTIONS:\n"
            "    --keyslot-cipher <type>\n"
            "    --slot-iterations <count>\n"
            "    --pbkdf <type>\n"
            "    --pbkdf_memory <count>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* luksfile = argv[2];
    const char* pwd = argv[3];
    const char* new_pwd = argv[4];

    if (vic_blockdev_open(luksfile, VIC_RDWR, 0, &dev) != VIC_OK)
        err("cannot open %s\n", luksfile);

    vic_kdf_t kdf =
    {
        .iterations = slot_iterations,
        .memory = pbkdf_memory,
    };

    if ((r = vic_luks_add_key(
        dev,
        keyslot_cipher,
        pbkdf,
        &kdf,
        pwd,
        strlen(pwd),
        new_pwd,
        strlen(new_pwd))) != VIC_OK)
    {
        err("%s() failed: %s\n", argv[1], vic_result_string(r));
    }

    vic_blockdev_close(dev);

    return 0;
}

static int luksChangeKey(int argc, const char* argv[])
{
    vic_blockdev_t* dev;
    vic_result_t r;

    /* Check usage */
    if (argc != 5)
    {
        fprintf(stderr,
            "Usage: %s %s <luksfile> <old-pwd> <new-pwd>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* luksfile = argv[2];
    const char* old_pwd = argv[3];
    const char* new_pwd = argv[4];

    if (vic_blockdev_open(luksfile, VIC_RDWR, 0, &dev) != VIC_OK)
        err("cannot open %s\n", luksfile);

    if ((r = vic_luks_change_key(
        dev,
        old_pwd,
        strlen(old_pwd),
        new_pwd,
        strlen(new_pwd))) != VIC_OK)
    {
        err("%s() failed: %s\n", argv[1], vic_result_string(r));
    }

    vic_blockdev_close(dev);

    return 0;
}

static int luksRemoveKey(int argc, const char* argv[])
{
    vic_blockdev_t* dev;
    vic_result_t r;

    /* Check usage */
    if (argc != 4)
    {
        fprintf(stderr,
            "Usage: %s %s <luksfile> <pwd>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* luksfile = argv[2];
    const char* pwd = argv[3];

    if (vic_blockdev_open(luksfile, VIC_RDWR, 0, &dev) != VIC_OK)
        err("cannot open %s\n", luksfile);

    if ((r = vic_luks_remove_key(dev, pwd, strlen(pwd))) != VIC_OK)
    {
        err("%s() failed: %s\n", argv[1], vic_result_string(r));
    }

    vic_blockdev_close(dev);

    return 0;
}

static int luksOpen(int argc, const char* argv[])
{
    vic_blockdev_t* dev;
    vic_result_t r;
    vic_key_t key;
    size_t key_size;

    /* Check usage */
    if (argc != 5)
    {
        fprintf(stderr,
            "Usage: %s %s <luksfile> <pwd> <dev-mapper-name>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* luksfile = argv[2];
    const char* pwd = argv[3];
    const char* name = argv[4];

    if (vic_blockdev_open(luksfile, VIC_RDWR, 0, &dev) != VIC_OK)
        err("cannot open %s\n", luksfile);

    if ((r = vic_luks_recover_master_key(
        dev,
        pwd,
        strlen(pwd),
        &key,
        &key_size)) != VIC_OK)
    {
        err("%s() failed: %s\n", argv[1], vic_result_string(r));
    }

    vic_blockdev_close(dev);

    if ((r = vic_luks_open(luksfile, name, &key, key_size)) != VIC_OK)
        err("%s() failed: %s\n", argv[1], vic_result_string(r));

    return 0;
}

static int luksOpenByKey(int argc, const char* argv[])
{
    vic_result_t r;
    vic_key_t key;
    size_t key_size;

    /* Check usage */
    if (argc != 5)
    {
        fprintf(stderr,
            "Usage: %s %s <luksfile> <keyfile> <dev-mapper-name>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* luksfile = argv[2];
    const char* keyfile = argv[3];
    const char* name = argv[4];

    if (vic_luks_load_key(keyfile, &key, &key_size) != VIC_OK)
        err("failed to load keyfile: %s", keyfile);

    if ((r = vic_luks_open(luksfile, name, &key, key_size)) != VIC_OK)
        err("%s() failed: %s\n", argv[1], vic_result_string(r));

    return 0;
}

static int luksClose(int argc, const char* argv[])
{
    vic_result_t r;

    /* Check usage */
    if (argc != 3)
    {
        fprintf(stderr,
            "Usage: %s %s <dev-mapper-name>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* name = argv[2];

    if ((r = vic_luks_close(name)) != VIC_OK)
        err("%s() failed: %s\n", argv[1], vic_result_string(r));

    return 0;
}

static int verityClose(int argc, const char* argv[])
{
    vic_result_t r;

    /* Check usage */
    if (argc != 3)
    {
        fprintf(stderr,
            "Usage: %s %s <dev-mapper-name>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* name = argv[2];

    if ((r = vic_luks_close(name)) != VIC_OK)
        err("%s() failed: %s\n", argv[1], vic_result_string(r));

    return 0;
}

static int _hexstr_to_salt(const char* hexstr, uint8_t buf[32])
{
    if (strlen(hexstr) != 64)
        return -1;

    for (size_t i = 0; i < 32; i++)
    {
        uint32_t x;

        if (sscanf(hexstr, "%02x", &x) != 1)
            return -1;

        buf[i] = x;
        hexstr += 2;
    }

    return 0;
}

static int verityDump(int argc, const char* argv[])
{
    vic_result_t r;
    vic_blockdev_t* hash_dev;
    const size_t blksz = 4096;

    /* Check usage */
    if (argc != 3)
    {
        fprintf(stderr,
            "Usage: %s %s <hashfile>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* hashfile = argv[2];
    const int hash_flags = VIC_RDONLY;

    if (vic_blockdev_open(hashfile, hash_flags, blksz, &hash_dev) != VIC_OK)
        err("cannot open hash file: %s\n", hashfile);

    if ((r = vic_verity_dump(hash_dev)) != VIC_OK)
        err("verityDump: failed: r=%u: %s\n", r, vic_result_string(r));

    vic_blockdev_close(hash_dev);

    return 0;
}

static int verityFormat(int argc, const char* argv[])
{
    const char* salt_opt = NULL;
    const char* uuid_opt = NULL;
    const char* hash_opt = NULL;
    bool need_superblock = true;
    uint8_t salt_buf[VIC_VERITY_MAX_SALT_SIZE];
    const uint8_t* salt = NULL;
    size_t salt_size = 0;
    vic_result_t r;
    uint8_t root_hash[256];
    size_t root_hash_size = sizeof(root_hash);
    vic_blockdev_t* data_dev;
    vic_blockdev_t* hash_dev;
    uint64_t data_block_size = 0;
    uint64_t hash_block_size = 0;

    /* Get --salt option */
    get_opt(&argc, argv, "--salt", &salt_opt);

    /* Get --uuid option */
    get_opt(&argc, argv, "--uuid", &uuid_opt);

    /* Get --hash option */
    get_opt(&argc, argv, "--hash", &hash_opt);

    /* Get --no-superblock option */
    if (get_opt(&argc, argv, "--no-superblock", NULL) == 0)
        need_superblock = false;

    /* Get --data-block-size option */
    get_opt_u64(&argc, argv, "--data-block-size", &data_block_size);

    /* Get --hash-block-size option */
    get_opt_u64(&argc, argv, "--hash-block-size", &hash_block_size);

    /* Check usage */
    if (argc != 4)
    {
        fprintf(stderr,
            "Usage: %s %s <datafile> <hashfile>\n"
            "OPTIONS:\n"
            "    --salt <value>\n"
            "    --uuid <value>\n"
            "    --hash <type>\n"
            "    --no-superblock\n"
            "    --data-block-size\n"
            "    --hash-block-size\n"
            "\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* datafile = argv[2];
    const char* hashfile = argv[3];
    const size_t blksz = 4096;
    const int data_flags = VIC_RDONLY;
    const int hash_flags = VIC_RDWR | VIC_CREATE | VIC_TRUNC;

    if (salt_opt)
    {
        salt_size = strlen(salt_opt) / 2;
        salt = salt_buf;

        if (salt_size > VIC_VERITY_MAX_SALT_SIZE)
            err("salt option is too long");

        if (_hexstr_to_salt(salt_opt, salt_buf) != 0)
            err("bad --salt option");
    }

    if (vic_blockdev_open(datafile, data_flags, blksz, &data_dev) != VIC_OK)
        err("cannot open data file: %s\n", datafile);

    if (vic_blockdev_open(hashfile, hash_flags, blksz, &hash_dev) != VIC_OK)
        err("cannot open hash file: %s\n", hashfile);

    if ((r = vic_verity_format(
        data_dev,
        hash_dev,
        hash_opt,
        uuid_opt,
        salt,
        salt_size,
        need_superblock,
        data_block_size,
        hash_block_size,
        root_hash,
        &root_hash_size)) != 0)
    {
        err("verityFormat: failed: r=%u: %s\n", r, vic_result_string(r));
    }

    vic_blockdev_close(data_dev);
    vic_blockdev_close(hash_dev);

    printf("\nRoot hash: ");
    vic_hexdump_flat(root_hash, root_hash_size);
    printf("\n\n");

    return 0;
}

static int verityOpen(int argc, const char* argv[])
{
    vic_result_t r;

    /* Check usage */
    if (argc != 6)
    {
        fprintf(stderr,
            "Usage: %s %s <datafile> <name> <hashfile> <root_hash>\n"
            "\n",
            argv[0],
            argv[1]);
        exit(1);
    }

    const char* datafile = argv[2];
    const char* name_opt = argv[3];
    const char* hashfile = argv[4];
    const char* root_hash_opt = argv[5];
    uint8_t* root_hash;
    size_t root_hash_size;
    vic_blockdev_t* data_dev;
    vic_blockdev_t* hash_dev;
    const int data_flags = VIC_RDONLY;
    const int hash_flags = VIC_RDONLY;

    if (vic_ascii_to_bin(root_hash_opt, &root_hash, &root_hash_size) != VIC_OK)
        err("bad root-hash argument");

    if (vic_blockdev_open(datafile, data_flags, 0, &data_dev) != VIC_OK)
        err("cannot open data file: %s\n", datafile);

    if (vic_blockdev_open(hashfile, hash_flags, 0, &hash_dev) != VIC_OK)
        err("cannot open hash file: %s\n", hashfile);

    if ((r = vic_verity_open(
        name_opt,
        data_dev,
        hash_dev,
        root_hash,
        root_hash_size)) != VIC_OK)
    {
        err("vic_verity_open() failed: %u: %s\n", r, vic_result_string(r));
    }

    vic_blockdev_close(data_dev);
    vic_blockdev_close(hash_dev);

    return 0;
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];

    /* Handle --trace option */
    {
        const char* trace = NULL;

        get_opt(&argc, argv, "--trace", &trace);

        if (trace)
        {
            if (strcmp(trace, "none") == 0)
                vic_trace_set_level(VIC_TRACE_NONE);
            else if (strcmp(trace, "fatal") == 0)
                vic_trace_set_level(VIC_TRACE_FATAL);
            else if (strcmp(trace, "error") == 0)
                vic_trace_set_level(VIC_TRACE_ERROR);
            else if (strcmp(trace, "warning") == 0)
                vic_trace_set_level(VIC_TRACE_WARNING);
            else if (strcmp(trace, "debug") == 0)
                vic_trace_set_level(VIC_TRACE_DEBUG);
            else
                err("bad --trace option: %s", trace);
        }
    }


    if (argc < 2)
    {
        fprintf(stderr, USAGE, arg0);
        exit(1);
    }

    if (strcmp(argv[1], "luksDump") == 0)
    {
        return luksDump(argc, argv);
    }
    else if (strcmp(argv[1], "luksFormat") == 0)
    {
        return luksFormat(argc, argv);
    }
    else if (strcmp(argv[1], "luksGetMasterKey") == 0)
    {
        return luksGetMasterKey(argc, argv);
    }
    else if (strcmp(argv[1], "luksAddKey") == 0)
    {
        return luksAddKey(argc, argv);
    }
    else if (strcmp(argv[1], "luksChangeKey") == 0)
    {
        return luksChangeKey(argc, argv);
    }
    else if (strcmp(argv[1], "luksRemoveKey") == 0)
    {
        return luksRemoveKey(argc, argv);
    }
    else if (strcmp(argv[1], "luksOpen") == 0)
    {
        return luksOpen(argc, argv);
    }
    else if (strcmp(argv[1], "luksOpenByKey") == 0)
    {
        return luksOpenByKey(argc, argv);
    }
    else if (strcmp(argv[1], "luksClose") == 0)
    {
        return luksClose(argc, argv);
    }
    else if (strcmp(argv[1], "verityDump") == 0)
    {
        return verityDump(argc, argv);
    }
    else if (strcmp(argv[1], "verityFormat") == 0)
    {
        return verityFormat(argc, argv);
    }
    else if (strcmp(argv[1], "verityOpen") == 0)
    {
        return verityOpen(argc, argv);
    }
    else if (strcmp(argv[1], "verityClose") == 0)
    {
        return verityClose(argc, argv);
    }
    else if (strcmp(argv[1], "cryptsetupLuksFormat") == 0)
    {
        return cryptsetupLuksFormat(argc, argv);
    }
    else if (strcmp(argv[1], "veritysetupOpen") == 0)
    {
        return veritysetupOpen(argc, argv);
    }
    else
    {
        err("Unknown action: %s", argv[1]);
    }

    return 0;
}
