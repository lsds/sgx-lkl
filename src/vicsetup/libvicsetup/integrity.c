#include <stdio.h>
#include <string.h>

#include "integrity.h"
#include "raise.h"

// Layout: SB | JOURNAL | [ DATA | TAGS ]*
//
// SB is padded out to 4096

static uint8_t _magic[8] = { 'i', 'n', 't', 'e', 'g', 'r', 't', '\0' };

static uint64_t _inverse_log2(uint8_t log)
{
    return 1 << (uint64_t)log;
}

vic_result_t vic_integrity_read_sb(
    vic_blockdev_t* device,
    uint64_t offset,
    vic_integrity_sb_t* sb)
{
    vic_result_t result = VIC_OK;
    const uint64_t blkno = offset / VIC_SECTOR_SIZE;
    uint8_t blk[VIC_SECTOR_SIZE];
    size_t block_size;

    CHECK(vic_blockdev_get_block_size(device, &block_size));

    if (block_size != VIC_SECTOR_SIZE)
        RAISE(VIC_BAD_BLOCK_SIZE);

    if (vic_blockdev_get(device, blkno, blk, 1) != 0)
        RAISE(VIC_FAILED);

    memcpy(sb, &blk, sizeof(vic_integrity_sb_t));

    if (memcmp(sb->magic, _magic, sizeof(sb->magic)) != 0)
        RAISE(VIC_NOT_FOUND);

done:
    return result;
}

vic_result_t vic_integrity_dump_sb(const vic_integrity_sb_t* sb)
{
    vic_result_t result;

    if (!sb || memcmp(sb->magic, _magic, sizeof(sb->magic)) != 0)
        RAISE(VIC_BAD_PARAMETER);

    printf("vic_luks_integrity_sb\n");
    printf("{\n");
    printf("  magic=%s (%02x %02x %02x %02x %02x %02x %02x %02x)\n", sb->magic,
        sb->magic[0], sb->magic[1], sb->magic[2], sb->magic[3],
        sb->magic[4], sb->magic[5], sb->magic[6], sb->magic[7]);
    printf("  version=%u\n", sb->version);
    printf("  log2_interleave_sectors=%u (%lu)\n",
        sb->log2_interleave_sectors,
        _inverse_log2(sb->log2_interleave_sectors));
    printf("  integrity_tag_size=%u\n", sb->integrity_tag_size);
    printf("  journal_sections=%u\n", sb->journal_sections);
    printf("  provided_data_sectors=%lu\n", sb->provided_data_sectors);
    printf("  flags=%u\n", sb->flags);
    printf("  log2_sectors_per_block=%u (%lu)\n",
        sb->log2_sectors_per_block,
        _inverse_log2(sb->log2_sectors_per_block));
    printf("  log2_blocks_per_bitmap_bit=%u (%lu)\n",
        sb->log2_blocks_per_bitmap_bit,
        _inverse_log2(sb->log2_blocks_per_bitmap_bit));
    printf("  recalc_sector=%lu\n", sb->recalc_sector);
    printf("}\n");

    result = VIC_OK;

done:
    return result;
}

bool vic_integrity_valid(const char* integrity)
{
    if (!integrity)
        return false;

    if (strcmp(integrity, "aead") == 0)
        return true;
    else if (strcmp(integrity, "hmac(sha256)") == 0)
        return true;
    else if (strcmp(integrity, "hmac(sha512)") == 0)
        return true;
    else if (strcmp(integrity, "cmac(aes)") == 0)
        return true;
    else if (strcmp(integrity, "poly1305") == 0)
        return true;

    return false;
}

size_t vic_integrity_tag_size(const char* integrity)
{
    if (!integrity)
        return (size_t)-1;

    if (strcmp(integrity, "aead") == 0)
        return 16;
    else if (strcmp(integrity, "hmac(sha256)") == 0)
        return 32;
    else if (strcmp(integrity, "hmac(sha512)") == 0)
        return 64;
    else if (strcmp(integrity, "cmac(aes)") == 0)
        return 16;
    else if (strcmp(integrity, "poly1305") == 0)
        return 16;

    return (size_t)-1;
}

size_t vic_integrity_key_size(const char* integrity)
{
    if (!integrity)
        return 0;

    if (strcmp(integrity, "aead") == 0)
        return 0;
    else if (strcmp(integrity, "hmac(sha256)") == 0)
        return 32;
    else if (strcmp(integrity, "hmac(sha512)") == 0)
        return 64;
    else if (strcmp(integrity, "cmac(aes)") == 0)
        return 0;
    else if (strcmp(integrity, "poly1305") == 0)
        return 0;

    return 0;
}
