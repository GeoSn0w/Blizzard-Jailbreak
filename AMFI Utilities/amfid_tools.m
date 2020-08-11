#import "amfid_tools.h"
#import "amfi_utils.h"
#import "amfid.h"

static unsigned int hash_rank(const CodeDirectory *cd){
    uint32_t type = cd->hashType;
    unsigned int n;
    for (n = 0; n < sizeof(hashPriorities) / sizeof(hashPriorities[0]); ++n)
        if (hashPriorities[n] == type){
            return n + 1;
        }
    return 0;
}

int get_hash(const CodeDirectory* directory, uint8_t dst[CS_CDHASH_LEN]) {
    uint32_t realsize = ntohl(directory->length);
    if (ntohl(directory->magic) != CSMAGIC_CODEDIRECTORY) {
        printf("AMFI TOOLS: [get_hash] wtf, not CSMAGIC_CODEDIRECTORY?!\n");
        return 1;
    }
    uint8_t out[CS_HASH_MAX_SIZE];
    uint8_t hash_type = directory->hashType;
    switch (hash_type) {
        case CS_HASHTYPE_SHA1:
            CC_SHA1(directory, realsize, out);
            break;
        case CS_HASHTYPE_SHA256:
        case CS_HASHTYPE_SHA256_TRUNCATED:
            CC_SHA256(directory, realsize, out);
            break;
        case CS_HASHTYPE_SHA384:
            CC_SHA384(directory, realsize, out);
            break;
        default:
            printf("AMFI TOOLS:[get_hash] Unknown hash type: 0x%x\n", hash_type);
            return 2;
    }
    memcpy(dst, out, CS_CDHASH_LEN);
    return 0;
}

int parse_superblob(uint8_t *code_dir, uint8_t dst[CS_CDHASH_LEN]) {
    int ret = 1;
    const CS_SuperBlob *sb = (const CS_SuperBlob *)code_dir;
    uint8_t highest_cd_hash_rank = 0;
    for (int n = 0; n < ntohl(sb->count); n++){
        const CS_BlobIndex *blobIndex = &sb->index[n];
        uint32_t type = ntohl(blobIndex->type);
        uint32_t offset = ntohl(blobIndex->offset);
        if (ntohl(sb->length) < offset) {
            printf("AMFI TOOLS: offset of blob #%d overflows superblob length\n", n);
            return 1;
        }
        const CodeDirectory *subBlob = (const CodeDirectory *)(code_dir + offset);
        if (type == CSSLOT_CODEDIRECTORY || (type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
            uint8_t rank = hash_rank(subBlob);
            if (rank > highest_cd_hash_rank) {
                ret = get_hash(subBlob, dst);
                highest_cd_hash_rank = rank;
            }
        }
    }
    return ret;
}
