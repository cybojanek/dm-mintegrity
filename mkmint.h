#define DM_MINTEGRITY_MAX_LEVELS 63
#define BLOCK_SIZE 4096
#define JBD_LEVEL_FACTOR 100

#define divide_up(x, y) (x == 0 ? x : (1 + ((x - 1) / y)))

struct mint_superblock {
	char name[8];             /**< Mint */
	uint32_t version;         /**< dm-mintegrity superblock version */
	char uuid[16];            /**< Device uuid */
	char hash_algorithm[32];  /**< Hash block algorithm */
	char hmac_algorithm[32];  /**< Hmac algorithm for root */
	uint32_t block_size;      /**< Size of one data/hash block */
	uint64_t data_blocks;     /**< Number of data blocks */
	uint32_t hash_blocks;     /**< Number of hash blocks */
	uint32_t jbd_blocks;      /**< Number of JBD blocks */
	uint16_t salt_size;       /**< Size of salt */
	char salt[128];           /**< Salt */
	char root[128];           /**< Root hash */     
	char hmac[128];           /**< Signed hmac of root */
	char pad[14];             /** Padding */
	char pad_block[BLOCK_SIZE - 512];
}__attribute__((packed));

///////////////////////////////////////////////////////////////////////////////
////////////////////////////////// Printing ///////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

/*! @brief Exit the program with code 1 and an error message
 *
 * @param message String to write to standard error
 */
#define exit_error(message) fprintf(stderr, "\033[31m%s\033[0m\n", message); exit(1);

/*! @brief Exit the program with code 1 and an error message
 *
 * Adds a newline to the end of the printed string
 *
 * @param fmt format string
 * @param ... args for format string
 */
#define exit_error_f(fmt, ...) fprintf(stderr, "\033[31m"fmt"\033[0m\n", ##__VA_ARGS__); exit(1);

/*! @brief Print a debug message to stderr
 *
 * Includes the file, and line number
 *
 * @param fmt format string
 * @param ... args for format string
 */
#ifdef DEBUG
#define debug(fmt, ...) fprintf(stderr, "\033[33m[DEBUG]\033[0m \033[35m%s:%d:\033[0m " fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define debug(fmr, ...)
#endif

/*! @brief Print an info message to stderr
 *
 * Includes the file, and line number
 *
 * @param fmt format string
 * @param ... args for format string
 */
#define info(fmt, ...) fprintf(stderr, "\033[32m[INFO]\033[0m " fmt"\n", ##__VA_ARGS__)

/*! @brief Print a log message to stderr
 *
 * Includes the file, and line number
 *
 * @param fmt format string
 * @param ... args for format string
 */
#define log(fmt, ...) fprintf(stderr, "\033[36m[LOG]\033[0m " fmt"\n", ##__VA_ARGS__)

/*! @brief Print a warning message to stderr
 *
 * Includes the file, and line number
 *
 * @param fmt format string
 * @param ... args for format string
 */
#define warn(fmt, ...) fprintf(stderr, "\033[31m[WARN]\033[0m \033[35m%s:%d:\033[0m " fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__)