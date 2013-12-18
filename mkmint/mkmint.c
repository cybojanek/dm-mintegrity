#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <uuid/uuid.h>
#include <linux/fs.h>

#include "mkmint.h"

/** @brief Print progress bar
 *
 * @param i Current index
 * @param n Total number of things
 * @param r How many times to update
 * @param w Total width of progress bar
 */
static inline void progress(uint64_t i, uint64_t n, uint8_t r, uint8_t w){
	if((n/r) != 0 && i % (n/r) != 0 && i != n){ return; }
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
void bytes_to_hex(const char *bytes, size_t len, char *out){
	for(size_t i = 0; i < len; i++){
		out += sprintf(out, "%02x", (uint8_t)bytes[i]);
	}
	*(out + 1) = 0;
}

/*! @brief Convert an ascii string of hex bytes to bytes
 *
 * Out should be of length len/2
 *
 * @param hex Hex string to convert
 * @param len Length of hex string
 * @param out[out] Output bytes
 *
 * @return 0 no error, -1 error in parsing
 */
int hex_to_bytes(const char *hex, size_t len, char *out){
	for(size_t i = 0; i < len / 2; i++){
		if(sscanf(hex + 2 * i, "%02x", &out[i]) != 1){
			return -1;
		}
	}
	return 0;
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
	printf("[ dm-mintegrity superblock ]\n");
	printf("Magic: %#0x\n", sb->magic);
	printf("Version: %u\n", sb->version);
	bytes_to_hex(sb->uuid, 16, buf);
	printf("UUID: %s\n", buf);
	printf("Hash_Type: %s\n", sb->hash_algorithm);
	printf("Hmac_Type: %s\n", sb->hmac_algorithm);
	printf("Block_Size: %u\n", sb->block_size);
	printf("Data_Blocks: %llu\n", sb->data_blocks);
	printf("Hash_Blocks: %u\n", sb->hash_blocks);
	printf("JB_Blocks: %u\n", sb->jb_blocks);
	printf("Salt_Size: %u\n", sb->salt_size);
	bytes_to_hex(sb->salt, sb->salt_size, buf);
	printf("Salt: %s\n", buf);
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
 * @param jb_blocks[out] Number of blocks needed for journal
 * @param pad_blocks[out] Number of blocks wasted
 * @param levels[out] Number of hash block levels (not including data level)
 *
 * @return 0 if ok else error
 */
int compute_block_numbers(uint64_t blocks, uint32_t block_size, uint32_t fanout,
	uint32_t jb_transactions, uint64_t *data_blocks, uint32_t *hash_blocks,
	uint32_t *jb_blocks, uint32_t *pad_blocks, uint32_t *levels,
	uint32_t *blocks_per_level, uint32_t hash_bytes){

	if(blocks < 6){
		exit_error_f("Not enough space! Need at least 6 blocks!");
		return -1;
	}
	// Remove one for superblocks
	blocks = blocks - 1;
	*pad_blocks = blocks;

	uint64_t low = 0;
	uint64_t high = blocks;
	uint32_t *bpl = (uint32_t*)malloc(sizeof(uint32_t) * DM_MINTEGRITY_MAX_LEVELS);


	while(high >= low && high != 0){
		uint64_t mid = low + divide_up((high - low), 2);  // Non overflow method
		uint64_t db = mid, used = 0;
		uint32_t hb = 0, jb = 0, pb = 0;
		uint32_t lev;
		// Number of hash blocks, levels needed for this many data blocks
		if(compute_hash_blocks(db, fanout, &lev, &hb, bpl) != 0){
			break; // Barf
		}

		// Number of jb blocks needed
		// How many levels will fit in a block, plus one more if not enough
		// for trasanction number
		uint32_t blocks_per_transaction = 1 + divide_up(lev, fanout) + 
			((lev % fanout * hash_bytes > block_size - sizeof(uint32_t)) ? 1 : 0);
		// Suerpblock, data blocks, hash transactions
		jb = 1 + jb_transactions * blocks_per_transaction;
		used = db + jb + hb;
		pb = blocks - used;

		// Result is better
		if(used <= blocks && pb < *pad_blocks){
			*data_blocks = db;
			*hash_blocks = hb;
			*jb_blocks = jb;
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
void hash(const EVP_MD *md, EVP_MD_CTX *mdctx, const char *input, size_t i,
	const char *salt, size_t s, char *out, uint32_t *hash_length){
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, salt, s);
	EVP_DigestUpdate(mdctx, input, i);
	EVP_DigestFinal_ex(mdctx, (unsigned char*)out, hash_length);
}

int main(int argc, char const *argv[]) {
	// Check for arguments
	if(argc != 8){
		exit_error_f("Usage: %s DEV BLOCK_SIZE JB_TRANSACTIONS HASH_TYPE SALT HMAC_TYPE SECRET", argv[0]);
	}
	const char *dev, *hash_type, *hmac_type, *salt_str, *secret;
	uint32_t block_size, jb_transactions;

	dev = argv[1];
	hash_type = argv[4];
	salt_str = argv[5];
	hmac_type = argv[6];
	secret = argv[7];

	// Open destination device
	int file;
	if((file = open(dev, O_RDWR)) < 0){
		exit_error_f("Could not open: '%s' for writing, %s", dev, strerror(errno));
	}

	// Get size
	// TODO: size of file in 512 chunks?
	struct stat file_stats;
	if(fstat(file, &file_stats) != 0){
		exit_error_f("Could not get file stats for: '%s', %s", dev, strerror(errno));
	}

	if(!(S_ISREG(file_stats.st_mode) || S_ISBLK(file_stats.st_mode))){
		exit_error_f("File is neither a regular file nor block device");
	}

	// Get block size
	if(sscanf(argv[2], "%u", &block_size) != 1){
		exit_error_f("Invalid block size: '%s'", argv[2]);
	}
	if(block_size < 512){
		exit_error_f("Invalid block size: '%u' < 512", block_size);
	}

	// Remainder check
	if(S_ISREG(file_stats.st_mode) && file_stats.st_size % block_size != 0){
		warn("File is not a multiple of block_size: %d. %llu bytes left over",
			block_size, file_stats.st_size % block_size);
	} else if(S_ISBLK(file_stats.st_mode))

	// Number of journal transactions
	if(sscanf(argv[3], "%u", &jb_transactions) != 1){
		exit_error_f("Invalid journal transaction number: '%s'", argv[3]);
	}
	if(jb_transactions == 0){
		exit_error_f("Journal transaction number has to be at least 1: %s", argv[3]);
	}

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
	uint32_t hmac_bytes = EVP_MD_size(md_hmac);

	// Parse and check salt
	char salt[128];
	if(strlen(salt_str) % 2 != 0){
		exit_error_f("Invalid hex salt: length not a multiple of 2");
	}
	if(strlen(salt_str) > 256){
		exit_error_f("Salt is too long. %lu > %d", strlen(salt_str), 256);
	}
	if(hex_to_bytes(salt_str, strlen(salt_str), (char*)salt) != 0){
		exit_error_f("Invalid hex salt: '%s'", salt_str);
	}

	// Calculate data size, hash block size, journal size
	// TODO: uh...this is 64 bits...
	uint64_t data_blocks = 0;
	uint32_t hash_blocks = 0;
	uint32_t jb_blocks = 0;
	uint32_t pad_blocks = 0;
	uint32_t *blocks_per_level = malloc(sizeof(uint32_t) * DM_MINTEGRITY_MAX_LEVELS);
	uint32_t levels = 0;
	uint64_t blocks;
	if(S_ISREG(file_stats.st_mode)){
		blocks = file_stats.st_size / block_size;
	} else if(S_ISBLK(file_stats.st_mode)){
		if(ioctl(file, BLKGETSIZE64, &blocks) != 0){
			exit_error_f("ioctl for block size failed: %s", strerror(errno));
		}
		blocks = blocks / block_size;
	}

	// Fanout
	uint32_t fanout = block_size / hash_bytes;

	// Use up entire block device
	compute_block_numbers(blocks, block_size, fanout, jb_transactions, &data_blocks,
		&hash_blocks, &jb_blocks, &pad_blocks, &levels, blocks_per_level, hash_bytes);
	
	// Result info
	info("Blocks: %llu = Superblock: 1, Data: %llu, Hash: %u, JB: %u, Pad: %u, Levels: %u",
			blocks, data_blocks, hash_blocks, jb_blocks, pad_blocks, levels);

	// Sanity check
	if(data_blocks + hash_blocks + jb_blocks + pad_blocks + 1!= blocks){
		warn("Data: %llu, Hash: %u, JB: %u, Pad: %u, Levels: %u",
			data_blocks, hash_blocks, jb_blocks, pad_blocks, levels);
		exit_error_f("Sanity check failed!: %llu != %llu",
			data_blocks + hash_blocks + jb_blocks + pad_blocks + 1, blocks);
	}

	// Calculate each hash block level
	char **hash_levels = (char**)malloc(sizeof(char*) * levels);
	char hash_output[EVP_MAX_MD_SIZE];
	uint32_t hash_length;
	char *zero_block = (char*)malloc(BLOCK_SIZE);
	bzero(zero_block, BLOCK_SIZE);

	char buf[128];
	// Data hash
	hash(md_hash, mdctx_hash, zero_block, BLOCK_SIZE, salt,
		strlen(salt_str) / 2, hash_output, &hash_length);

	// Now loop through each level
	for(uint32_t i = 0; i < levels; i++){
		hash_levels[i] = (char*)malloc(BLOCK_SIZE);
		// Fill block with hashes - padding is zeros
		bzero(hash_levels[i], BLOCK_SIZE);
		for(uint32_t f = 0; f < fanout; f++){
			for(int b = 0; b < hash_bytes; b++){
				hash_levels[i][f * hash_length + b] = hash_output[b];
			}
		}
		// Compute hash of this level for next iteration/root
		hash(md_hash, mdctx_hash, hash_levels[i], BLOCK_SIZE, salt, strlen(salt_str) / 2,
			hash_output, &hash_length);
	}

	// Write out hash superblock
	struct mint_superblock *msb = malloc(sizeof(struct mint_superblock));
	// Zero out everything
	bzero(msb, sizeof(struct mint_superblock));
	// Magic
	msb->magic = 0x796c694c;
	// Version
	msb->version = 1;
	// Make a new uuid!
	uuid_t uuid;
	uuid_generate(uuid);
	// TODO: is there a better way of doing this?
	memcpy(&msb->uuid, &uuid, 16);
	// Copy hash algorithm name
	stpcpy(msb->hash_algorithm, hash_type);
	// Copy hmac algorithm name
	stpcpy(msb->hmac_algorithm, hmac_type);
	// Block size!
	msb->block_size = BLOCK_SIZE;
	// Set block numbers
	msb->data_blocks = data_blocks;
	msb->hash_blocks = hash_blocks;
	msb->jb_blocks = jb_blocks;
	// Set salt size
	msb->salt_size = strlen(salt_str) / 2;
	// Copy salt
	memcpy(msb->salt, salt, msb->salt_size);
	// Set root hash
	memcpy(msb->root, hash_output, hash_length);
	// Set hmac
	// TODO: calculate hmac
	memcpy(msb->hmac, hash_output, hash_length);
	// Write it out!
	if(write(file, msb, sizeof(struct mint_superblock)) < 0){
		exit_error_f("Failed to write MSB: %s", strerror(errno));
	}

	// Write out hash block levels
	uint32_t blocks_written = 0;
	info("Writing hash blocks...");
	uint32_t h_written = 1;
	for(int i = levels - 1; i >= 0; i--){
		for(uint32_t j = 0; j < blocks_per_level[i]; j++){
			// debug("level: %u, block: %u", i, j);
			progress(h_written++, hash_blocks, 100, 79);
			if(write(file, hash_levels[i], BLOCK_SIZE) < 0){
				exit_error_f("Failed to write hash block: %u, %s",
					h_written - 1, strerror(errno));
			}
			blocks_written++;
		}
	}
	fprintf(stderr, "\n");

	// Initialize journal
	struct mint_journal_superblock *mjsb = (struct mint_journal_superblock*)malloc(sizeof(struct mint_journal_superblock));
	bzero(mjsb, sizeof(struct mint_journal_superblock));
	// Magic
	mjsb->magic[0] = 0x6c; mjsb->magic[1] = 0x69; mjsb->magic[2] = 0x6c; mjsb->magic[3] = 0x79;
	mjsb->magic[4] = 0x6d; mjsb->magic[5] = 0x75; mjsb->magic[6] = 0x66; mjsb->magic[7] = 0x66;
	mjsb->magic[8] = 0x69; mjsb->magic[9] = 0x6e; mjsb->magic[10] = 0x00; mjsb->magic[11] = 0x00;
	mjsb->magic[12] = 0x00; mjsb->magic[13] = 0x00; mjsb->magic[14] = 0x00; mjsb->magic[15] = 0x00;
	// Maximum number of supported transactions
	mjsb->transaction_capacity = jb_transactions;
	// Current amount of transactions - 0
	mjsb->transaction_fill = 0;
	// Block size
	mjsb->block_size = BLOCK_SIZE;
	// Number of blocks - including journal
	mjsb->num_blocks = jb_blocks;
	// Number of hash levels
	mjsb->hash_levels = levels;
	// Number of bytes in a hash
	mjsb->hash_bytes = hash_bytes;
	// Clean
	mjsb->state = 0;
	// Zeroed
	// mjsb->hmac = 
	// Zeroed
	// mjsb->pad
	// Zeroed
	// mjsb->pad_block

	info("Writing journal...");
	// Doesn't matter that the rest are the same - just duplicate the block
	// everywhere - I think even mkfs.ext3/ext4 does it the same way
	for(uint32_t i = 0 ; i < jb_blocks; i++){
		progress(i + 1, jb_blocks, 100, 79);
		if(write(file, mjsb, sizeof(struct mint_journal_superblock)) < 0){
			exit_error_f("Failed to write journal block: %u, %s", i,
				strerror(errno));
		}
	}
	fprintf(stderr, "\n");

	// Zero out data
	info("Writing data blocks...");
	for(uint64_t i = 0; i < data_blocks; i++){
		progress(i + 1, data_blocks, 100, 79);
		if(write(file, zero_block, BLOCK_SIZE) < 0){
			exit_error_f("Failed to write data block: %u, %s", i,
				strerror(errno));
		}
	}
	fprintf(stderr, "\n");

	print_superblock(msb);
	bytes_to_hex(msb->root, hash_bytes, buf);
	printf("dmsetup create meow --table \"%u %llu mintegrity %s %u %u %u %llu %s %s %s %s %s\"\n",
		0,
		data_blocks * (BLOCK_SIZE / 512),   // Size of device given to device mapper
		// Mintegrity options
		dev,           // String of block device
		BLOCK_SIZE,    // Block size
		hash_blocks,   // Number of hash blocks
		jb_blocks,     // Number of journaling blocks
		data_blocks,   // Number of data blocks
		hash_type,     // Hash type
		buf,           // Root digest to verity
		salt_str,      // Salt
		hmac_type,     // Hash type for hmac
		secret         // Secret for hmac
		);

	free(mjsb);
	free(msb);
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
