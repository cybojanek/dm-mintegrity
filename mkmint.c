#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <sys/stat.h>

#include <uuid/uuid.h>

#include "mkmint.h"

const char *dev, *hash_type, *hmac_type, *salt, *secret;

/** @brief Print progress bar
 *
 * @param i Current index
 * @param n Total number of things
 * @param r How many times to update
 * @param w Total width of progress bar
 */
static inline void progress(uint64_t i, uint64_t n, uint8_t r, uint8_t w){
	if(i % (n/r) != 0 && i != n){ return; }
	char line[w + 1];
	sprintf(line, " %3llu%% [", i != n ? i * 100 / n : 100);
	uint8_t points = i != n ? 7 + (w - 9) * i / n : 7 + w - 9;
	for(uint8_t i = 7; i < points; i++){
		line[i] = '=';
	}
	for(uint8_t i = points; i < w - 2; i++){
		line[i] = ' ';
	}
	line[w - 2] = ']';
	line[w - 1] = '\r';
	line[w] = 0;
	fprintf(stderr, "%s", line);
}

/** @brief Convert an array of bytes to a hex strings
 *
 * Caller's responsibility to check that out is long enough
 *
 * @param bytes Bytes to convert
 * @param len Number of bytes
 * @param out[out] Null terminated hex string of bytes
 */
void bytes_to_hex(char *bytes, size_t len, char *out){
	for(size_t i = 0; i < len; i++){
		out += sprintf(out, "%02x", (uint8_t)bytes[i]);
	}
	*(out + 1) = 0;
}

/** @brief Print out the superblock struct to stdout
 *
 * @param sb Superblock
 */
void print_superblock(struct mint_superblock *sb){
	char *buf = (char*)(malloc(4096));
	const EVP_MD *md;
	md = EVP_get_digestbyname(sb->hash_algorithm);
	uint32_t hash_bytes = EVP_MD_size(md);
	md = EVP_get_digestbyname(sb->hmac_algorithm);
	uint32_t hmac_bytes = EVP_MD_size(md);
	printf("Name: %s\n", sb->name);
	printf("Version: %u\n", sb->version);
	bytes_to_hex(sb->uuid, 16, buf);
	printf("UUID: %s\n", buf);
	printf("Hash_Type: %s\n", sb->hash_algorithm);
	printf("Hmac_Type: %s\n", sb->hmac_algorithm);
	printf("Block_Size: %u\n", sb->block_size);
	printf("Data_Blocks: %llu\n", sb->data_blocks);
	printf("Hash_Blocks: %u\n", sb->hash_blocks);
	printf("JBD_Blocks: %u\n", sb->jbd_blocks);
	printf("Salt_Size: %u\n", sb->salt_size);
	printf("Salt: %s\n", sb->salt);
	bytes_to_hex(sb->root, hash_bytes, buf);
	printf("Root_Hash: %s\n", buf);
	bytes_to_hex(sb->hmac, hmac_bytes, buf);
	printf("Hmac_Hash: %s\n", buf);
	free(buf);
}

/** @brief Compute the number of hash blocks needed
 *
 * Does not include empty branches in computation
 *
 * @param data_blocks Number of data blocks
 * @param fanout Tree fanout
 * @param levels[out] Number of tree levels (not including data level)
 * @param hash_blocks[out] Number of necessary hash blocks
 *
 * @return Non zero value means error, else 0
 */
int compute_hash_blocks(uint64_t data_blocks, uint32_t fanout,
	uint32_t *levels, uint32_t *hash_blocks, uint32_t *blocks_per_level){
	*levels = 0;
	*hash_blocks = 0;
	uint32_t i = divide_up(data_blocks, fanout);
	while(i != 1){
		blocks_per_level[*levels] = i;
		*hash_blocks += i;
		*levels += 1;
		i = divide_up(i, fanout);
	}
	// Top level
	blocks_per_level[*levels] = 1;
	*levels += 1;
	*hash_blocks += 1;
	if(i == 0){
		return -1;
	} else {
		return 0;
	}
}

/** @brief Compute the optimal number of data blocks to fill disk
 *
 * @param blocks Total number of blocks to work with
 * @param fanout Number of hashes that fit in a hash block
 * @param data_blocks[out] Number of data blocks writeable
 * @param hash_blocks[out] Number of blocks needed for hashes
 * @param jbd_blocks[out] Number of blocks needed for journal
 * @param pad_blocks[out] Number of blocks wasted (could be repurposed for JBD)
 * @param levels[out] Number of hash block levels (not including data level)
 *
 * @return 0 if ok else error
 */
int compute_block_numbers(uint64_t blocks, uint32_t fanout,
	uint64_t *data_blocks, uint32_t *hash_blocks, uint32_t *jbd_blocks,
	uint32_t *pad_blocks, uint32_t *levels, uint32_t *blocks_per_level){

	// Remove one for superblocks
	blocks = blocks - 1;
	*pad_blocks = blocks;

	uint64_t low = 0, high = blocks;
	uint32_t *bpl = (uint32_t*)malloc(sizeof(uint32_t) * DM_MINTEGRITY_MAX_LEVELS);

	while(high >= low && high != 0){
		uint64_t mid = low + ((high - low) / 2);  // Non overflow method
		uint64_t db = mid, used = 0;
		uint32_t hb = 0, jb = 0, pb = 0;
		uint32_t lev;
		// Number of hash blocks, levels needed for this many data blocks
		if(compute_hash_blocks(db, fanout, &lev, &hb, bpl) != 0){
			break; // Barf
		}

		// Number of jbd blocks needed
		jb = JBD_LEVEL_FACTOR * lev;
		used = db + jb + hb;
		pb = blocks - used;

		// Result is better
		if(used <= blocks && pb < *pad_blocks){
			*data_blocks = db;
			*hash_blocks = hb;
			*jbd_blocks = jb;
			*pad_blocks = pb;
			*levels = lev;
			for(int i = 0; i < *levels; i++){
				blocks_per_level[i] = bpl[i];
			}
		}

		if(used > blocks){ // Too many - go down
			high = mid - 1;
		} else if(used < blocks){ // Not enough - go up
			low = mid + 1;
		} else { // Optimal! Wow!
			break;
		}
	}
	free(bpl);
	// Failed at first try
	if(*pad_blocks == blocks){
		return -1;
	} else {
		return 0;
	}
}

/** @brief Compute the hash of some input with a salt
 *
 * Salt length can be 0. Updates are: update(salt), update(input), update(salt)
 *
 * @param md Message digest algorithm
 * @param mdctx Message digest context
 * @param input Input bytes
 * @param i Number of input bytes
 * @param salt Salt bytes
 * @param s Number of salt bytes
 * @param out[out] Binary digest output
 * @param hash_length[out] Size of digest in bytes
 */
void hash(const EVP_MD *md, EVP_MD_CTX *mdctx, const uint8_t *input, size_t i,
	const uint8_t *salt, size_t s, uint8_t *out, uint32_t *hash_length){
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, salt, s);
	EVP_DigestUpdate(mdctx, input, i);
	EVP_DigestUpdate(mdctx, salt, s);
	EVP_DigestFinal_ex(mdctx, out, hash_length);
}

int main(int argc, char const *argv[]) {
	// Check for arguments
	if(argc != 6){
		exit_error_f("Usage: %s DEV HASH_TYPE SALT HMAC_TYPE SECRET", argv[0]);
	}
	dev = argv[1];
	hash_type = argv[2];
	salt = argv[3];
	hmac_type = argv[4];
	secret = argv[5];

	OpenSSL_add_all_digests();

	// Block hash algorithm
	EVP_MD_CTX *mdctx_hash = EVP_MD_CTX_create();
	const EVP_MD *md_hash;
	md_hash = EVP_get_digestbyname(hash_type);
	if(!md_hash){
		exit_error_f("Unsupported hash type: %s", hash_type);
	}
	uint32_t hash_bytes = EVP_MD_size(md_hash);

	// Hmac algorithm
	EVP_MD_CTX *mdctx_hmac = EVP_MD_CTX_create();
	const EVP_MD *md_hmac;
	md_hmac = EVP_get_digestbyname(hmac_type);
	if(!md_hmac){
		exit_error_f("Unsupported hmac type: %s", hmac_type);
	}
	// uint32_t hmac_bytes = EVP_MD_size(md_hmac);

	// Check salt
	if(strlen(salt) > 128){
		exit_error_f("Salt has to be of length: [0, 128]");
	}

	// Open destination device
	int file;
	if((file = open(dev, O_RDWR)) == -1){
		exit(1);
	}

	// Get size
	struct stat file_stats;
	if(fstat(file, &file_stats) == -1){
		exit(1);
	}

	debug("Size of: %s is %lld bytes", dev, file_stats.st_size);

	// Calculate data size, hash block size, journal size
	// TODO: uh...this is 64 bits...
	uint64_t data_blocks = 0;
	uint32_t hash_blocks = 0, jbd_blocks = 0, pad_blocks = 0;
	uint32_t *blocks_per_level = malloc(sizeof(uint32_t) * DM_MINTEGRITY_MAX_LEVELS);
	uint32_t levels = 0;
	uint64_t blocks = file_stats.st_size / BLOCK_SIZE;

	// Remainder check
	if(file_stats.st_size % BLOCK_SIZE != 0){
		warn("File is not a multiple of BLOCK_SIZE: %d. %llu bytes left over",
			BLOCK_SIZE, file_stats.st_size % BLOCK_SIZE);
	}

	// Fanout
	uint32_t fanout = BLOCK_SIZE / hash_bytes;

	// Use up entire block device
	compute_block_numbers(blocks, fanout, &data_blocks,
		&hash_blocks, &jbd_blocks, &pad_blocks, &levels, blocks_per_level);
	
	// Result info
	info("Blocks --> Data: %llu, Hash: %u, JBD: %u, Pad: %u, Levels: %u",
			data_blocks, hash_blocks, jbd_blocks, pad_blocks, levels);

	// Sanity check
	if(data_blocks + hash_blocks + jbd_blocks + pad_blocks + 1!= blocks){
		warn("Data: %llu, Hash: %u, JBD: %u, Pad: %u, Levels: %u",
			data_blocks, hash_blocks, jbd_blocks, pad_blocks, levels);
		exit_error_f("Sanity check failed!: %llu != %llu",
			data_blocks + hash_blocks + jbd_blocks + pad_blocks + 1, blocks);
	}

	info("Total blocks: %llu", blocks);
	info("Fanout: %u", fanout);


	// Calculate each hash block level
	uint8_t **hash_levels = (uint8_t**)malloc(sizeof(uint8_t*) * levels);
	uint8_t hash_output[EVP_MAX_MD_SIZE];
	uint32_t hash_length;
	uint8_t *zero_block = (uint8_t*)malloc(BLOCK_SIZE);
	bzero(zero_block, BLOCK_SIZE);

	// Data hash
	hash(md_hash, mdctx_hash, zero_block, BLOCK_SIZE, (uint8_t*)salt,
		strlen(salt), hash_output, &hash_length);

	// Now loop through each level
	for(uint32_t i = 0; i < levels; i++){
		hash_levels[i] = (uint8_t*)malloc(BLOCK_SIZE);
		bzero(hash_levels[i], BLOCK_SIZE);
		for(uint32_t f = 0; f < fanout; f++){
			memcpy(hash_levels[i] + (f * hash_length), hash_output, hash_length);
		}
		hash(md_hash, mdctx_hash, hash_levels[i], BLOCK_SIZE, (uint8_t*)salt, strlen(salt),
			hash_output, &hash_length);
	}

	// Write out hash superblock
	struct mint_superblock sb;
	// Zero out everything
	bzero(&sb, sizeof(struct mint_superblock));
	// Name
	stpcpy(sb.name, "mint");
	// Version
	sb.version = 1;
	// Make a new uuid!
	uuid_t uuid;
	uuid_generate(uuid);
	// TODO: is there a better way of doing this?
	memcpy(&sb.uuid, &uuid, 16);
	// Copy hash algorithm name
	stpcpy(sb.hash_algorithm, hash_type);
	// Copy hmac algorithm name
	stpcpy(sb.hmac_algorithm, hmac_type);
	// Block size!
	sb.block_size = BLOCK_SIZE;
	// Set block numbers
	sb.data_blocks = data_blocks;
	sb.hash_blocks = hash_blocks;
	sb.jbd_blocks = jbd_blocks;
	// Set salt size
	sb.salt_size = strlen(salt);
	// Copy salt
	stpcpy(sb.salt, salt);
	// Set root hash
	memcpy(sb.root, hash_output, hash_length);
	// Set hmac
	hash(md_hmac, mdctx_hmac, (uint8_t*)sb.root, hash_length, (uint8_t*)secret,
		strlen(secret), (uint8_t*)sb.hmac, &hash_length);
	// Write it out!
	write(file, &sb, sizeof(struct mint_superblock));

	// Write out hash block levels
	info("Writing hash blocks");
	uint32_t h_written = 0;
	for(int i = levels - 1; i >= 0; i--){
		for(uint32_t j = 0; j < blocks_per_level[i]; j++){
			progress(++h_written, hash_blocks, 100, 79);
			write(file, hash_levels[i], BLOCK_SIZE);
		}
	}
	fprintf(stderr, "\n");

	// Initialize journal

	// Zero out data
	info("Writing data blocks");
	for(uint64_t i = 0; i < data_blocks; i++){
		progress(i + 1, data_blocks, 100, 79);
		write(file, zero_block, BLOCK_SIZE);
	}
	fprintf(stderr, "\n");

	print_superblock(&sb);

	free(blocks_per_level);
	free(zero_block);
	for(int i = 0; i < levels; i++){
		free(hash_levels[i]);
	}
	free(hash_levels);
	close(file);
	EVP_MD_CTX_destroy(mdctx_hash);
	return 0;
}