/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * dm-mintegrity Author: Jan Kasiak <j.kasiak@gmail.com>
 * Based on dm-verity driver by: Mikulas Patocka <mpatocka@redhat.com>
 * Based on Chromium dm-verity driver (C) 2011 The Chromium OS Authors
 *
 * This file is released under the GPLv2.
 *
 * In the file "/sys/module/dm_mintegrity/parameters/prefetch_cluster" you can set
 * default prefetch value. Data are read in "prefetch_cluster" chunks from the
 * hash device. Setting this greatly improves performance when data and hash
 * are on the same disk on different partitions on devices with poor random
 * access behavior.
 */

#include <crypto/hash.h>
#include <linux/device-mapper.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/rbtree.h>

#define DM_MSG_PREFIX			"mintegrity"

#define DM_MINTEGRITY_DEFAULT_PREFETCH_SIZE	262144

#define DM_MINTEGRITY_MAX_LEVELS		63

static unsigned dm_mintegrity_prefetch_cluster = DM_MINTEGRITY_DEFAULT_PREFETCH_SIZE;

module_param_named(prefetch_cluster, dm_mintegrity_prefetch_cluster, uint, S_IRUGO | S_IWUSR);

#define MJ_MAGIC 0x594c494c
/* Mint Journal Nothing Block */
#define TYPE_MJNB 0
/* Mint Journal Super Block */
#define TYPE_MJSB 1
/* Mint Journal Descriptor Block */
#define TYPE_MJDB 2
/* Mint Journal Commit Block */
#define TYPE_MJCB 3

/* Tag and transaction revoked */
#define J_TAG_REVOKE 1
/* Last tag */
#define J_TAG_LAST   2

#define J_PAGE_ORDER_SIZE 2
#define J_PAGE_CHUNK_SIZE (1 << J_PAGE_ORDER_SIZE)

// #define DEBUG_READ_ONLY
// #define DEBUG_NOP_JOURNAL_WRITE
// #define DEBUG_DONT_USE_JOURNAL
// #define DEBUG_DONT_USE_JOURNALT_MARK_MERKLE_DIRTY
// #define DEBUG_SKIP_WRITE_HASH_UPDATE

struct mint_journal_header {
	uint32_t magic;     /* 0x594c494c */
	uint32_t type;      /* Super/Descriptor/Commit Block */
	uint32_t sequence;  /* Sequence number */
	uint32_t options;   /* Options */
};

struct mint_journal_block_tag {
	uint32_t low;      /* Destination sector low */
	uint32_t high;     /* Destination sector high */
	uint8_t options;  /* Last or bits for escaped blocks */
}__attribute__((packed));

struct mint_journal_superblock {
	struct mint_journal_header header;
	uint32_t tail;        /* Circular buffer tail position */
	char state;           /* Clean, Dirty */
	// Previous hmac
	// Next hmac
};

struct journal_block {
	uint8_t *data;
	struct dm_mintegrity *v;
	struct completion *event;
	struct bio bio;
	struct bio_vec bio_vec[J_PAGE_CHUNK_SIZE];
	atomic_t n;
	atomic_t available;
	atomic_t finished;
	struct semaphore sema;
	int size;
	bool hasExtra;
}__attribute__((aligned(8)));

struct data_block {
	struct dm_mintegrity *v;
	struct list_head list;

	struct data_block *prev;
	struct data_block *next;

	u8 *data;
	struct rb_node node;
	sector_t sector;
	struct bio bio;
	struct bio_vec bio_vec;
	struct semaphore sema;
	atomic_t ref_count;
	struct completion event;
	bool dirty;
	atomic_t writers;
	// TODO: does this need to be atomic?
	atomic_t hash_verified;         /* Buffer has been verified */
	struct rw_semaphore lock;       /* RW semaphore lock for async write back */
};

struct dm_mintegrity {
	// Block device
	struct dm_dev *dev;
	struct dm_dev *data_dev;
	struct dm_target *ti;

	// Hash
	char *alg_name;        /* Hash algorithm name */
	char *hmac_alg_name;   /* HMAC hash algorithm name */

	uint32_t salt_size;    /* Size of salt */
	uint32_t secret_size;  /* Size of HMAC secret */

	uint8_t *zero_digest;  /* Hash digest of a zero block */
	uint8_t *root_digest;  /* Hash digest of the root block */
	uint8_t *salt;		   /* salt: its size is salt_size */
	uint8_t *secret;       /* HMAC secret: its size is secret_size */
	uint8_t *hmac_digest;  /* HMAC digest */

	struct crypto_shash *tfm;       /* Hash algorithm */
	struct crypto_shash *hmac_tfm;  /* HMAC hash algorithm */
	struct shash_desc *hmac_desc;   /* HMAC shash object */

	uint32_t digest_size;          /* hash digest size */
	uint32_t hmac_digest_size;	   /* HMAC hash digest size */

	uint32_t shash_descsize;       /* crypto temp space size */

	// State
	int hash_failed;	/* set to 1 if hash of any block failed */
	int created;

	// Sector numbers
	sector_t hash_start;	    /* hash start in blocks */
	sector_t journal_start;	    /* journal start in blocks */
	sector_t data_start;	    /* data start in blocks */
	sector_t data_start_shift;  /* data offset in 512-byte sectors */

	sector_t hash_blocks;	    /* the number of hash blocks */
	sector_t journal_blocks;    /* the number of journal blocks */
	sector_t data_blocks;	    /* the number of data blocks */

	// Block size numbers
	uint8_t dev_block_bits;	      /* log2(blocksize) */
	uint8_t hash_per_block_bits;  /* log2(hashes in hash block) */
	uint32_t dev_block_bytes;     /* Number of bytes in a device block */

	// Other
	unsigned char levels;	/* the number of tree levels */
	mempool_t *journal_page_mempool;
	mempool_t *journal_block_mempool;
	mempool_t *data_block_mempool;
	mempool_t *data_page_mempool;

	// Work queues
	struct workqueue_struct *workqueue;     /* workqueue for processing reads */

	// Locks
	struct rw_semaphore j_lock;  /* global journal read/write lock */

	// Journal
	struct task_struct *j_background_thread;  /* Background journal thread */
	struct mint_journal_superblock j_sb_header;  /* Current journal header */

	struct journal_block *j_ds_buffer;  /* Journal descriptor buffer */

	struct semaphore request_limit;
	atomic_t j_fill;     /* Number of blocks in journal - need atomic due to writeback */
	atomic_t j_commit_outstanding;

	uint32_t j_ds_fill;  /* Number of tags in current descriptor buffer */
	uint32_t j_ds_max;   /* Max number of tags in descriptor buffer */
	uint32_t j_bpt;      /* Number of blocks required per transaction */

	struct journal_block *jbs;
	atomic_t jbs_available;
	atomic_t jbs_finished;

	/* starting blocks for each tree level. 0 is the lowest level. */
	sector_t hash_level_block[DM_MINTEGRITY_MAX_LEVELS];

	struct rw_semaphore data_tree_semaphore;
	struct rw_semaphore hash_tree_semaphore;
	struct rb_root root_data_node;
	struct rb_root root_hash_node;


	struct list_head clean_hash_list;
	struct list_head dirty_hash_list;

	int num_hash_nodes;
	bool two_disks;
};

struct dm_mintegrity_io {
	struct dm_mintegrity *v;  /* dm-mintegrity instance info */
    struct bvec_iter iter;
	sector_t block;     /* Start of block IO */

	uint32_t n_blocks;  /* Number of blocks in IO */

	struct work_struct work;  /* Work instance for read/write queue */

	bio_end_io_t *orig_bi_end_io;
	void *orig_bi_private;

	// Fix for race condition
	u8 *previous_hash;

	/*
	 * Five variably-size fields follow this struct:
	 *
	 * struct dm_buffer[v->levels + 1];
	 * struct dm_buffer[v->j_bpt];
	 * u8 hash_desc[v->shash_descsize];
	 * u8 real_digest[v->digest_size];
	 * u8 want_digest[v->digest_size];
	 *
	 * To access them use: io_hash_desc(), io_real_digest(), io_want_digest(),
	 * io_dm_buffers(), and io_dm_j_buffers().
	 *
	 * Keep attribute aligned, because struct * need to be aligned at 8 byte
	 * boundaries.
	 */
}__attribute__((aligned(8)));


/* Search tree for sector block - assumes exclusive access
 */
static struct data_block *tree_search(struct rb_root *root, sector_t sector)
{
	struct rb_node *node = root->rb_node;
	while (node) {
		struct data_block *data = container_of(node, struct data_block, node);
		if (sector < data->sector) {
			node = node->rb_left;
		} else if (sector > data->sector) {
			node = node->rb_right;
		} else {
			return data;
		}
	}
	return NULL;
}

/* Insert sector block into tree - assumes exclusive access
 */
static int tree_insert(struct rb_root *root, struct data_block *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct data_block *this = container_of(*new, struct data_block, node);
		parent = *new;
		if (data->sector < this->sector) {
			new = &((*new)->rb_left);
		} else if (data->sector > this->sector) {
			new = &((*new)->rb_right);
		} else {
			return 0;
		}
	}
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
	return 1;
}

/* Release data block memory to allocator if ref count is zero
 */
static void data_block_release(struct data_block *d)
{
	if (atomic_dec_return(&(d->ref_count)) == 0) {
		mempool_free(d->data, d->v->data_page_mempool);
		mempool_free(d, d->v->data_block_mempool);
	}
}

/* Release a hash block, adding it to the clean list if its ref count is 0
 * and its not dirty. Block stays in tree.
 */
static void hash_block_release(struct data_block *d)
{
	struct dm_mintegrity *v = d->v;
	down_write(&v->hash_tree_semaphore);
	if (atomic_dec_return(&d->ref_count) == 0 && !d->dirty) {
		list_add_tail(&d->list, &v->clean_hash_list);
	}
	up_write(&v->hash_tree_semaphore);
}

static void hash_block_mark_dirty(struct data_block *d)
{
	struct dm_mintegrity *v = d->v;
	down_write(&v->hash_tree_semaphore);
	if (!d->dirty) {
		d->dirty = true;
		list_add_tail(&d->list, &v->dirty_hash_list);
	}
	up_write(&v->hash_tree_semaphore);
}

static void mintegrity_data_write_end_io(struct bio *bio, int error)
{
	// TODO: error
	struct data_block *d = bio->bi_private;
	data_block_release(d);
}

static void mintegrity_hash_read_end_io(struct bio *bio, int error)
{
	// TODO: error
	struct data_block *d = bio->bi_private;
	complete_all(&d->event);
}

static void mintegrity_hash_write_end_io(struct bio *bio, int error) {
	// TODO: error
	struct data_block *d = bio->bi_private;
	complete_all(&d->event);
}

struct data_block *get_data_block(struct dm_mintegrity *v, sector_t sector,
	bool read)
{
	struct data_block *d = NULL;

	read ? down_read(&v->data_tree_semaphore) : down_write(&v->data_tree_semaphore);

	d = tree_search(&v->root_data_node, sector);
	if (!read && d == NULL) {
		struct bio *bio;
		// TODO: check alloc
		d = mempool_alloc(v->data_block_mempool, GFP_NOIO);
		memset(d, 0, sizeof(struct data_block));
		d->data = mempool_alloc(v->data_page_mempool, GFP_NOIO);
		d->sector = sector;
		d->v = v;
		// 2 - because we need to keep it until we right it out
		atomic_set(&(d->ref_count), 2);

		bio = &d->bio;
		bio_init(bio);
		bio->bi_iter.bi_sector = sector << (v->dev_block_bits - SECTOR_SHIFT);
		bio->bi_bdev = (v->data_dev ? v->data_dev->bdev : v->dev->bdev);
		bio->bi_rw = WRITE;
		bio->bi_max_vecs = 1;
		bio->bi_io_vec = &d->bio_vec;

		bio->bi_end_io = mintegrity_data_write_end_io;
		bio->bi_private = d;
		BUG_ON(!bio_add_page(bio, virt_to_page(d->data), 4096, 0));
		BUG_ON(!tree_insert(&v->root_data_node, d));
	} else if (d != NULL) {
		atomic_inc(&(d->ref_count));
	}

	read ? up_read(&v->data_tree_semaphore) : up_write(&v->data_tree_semaphore);

	return d;
}

struct data_block *get_hash_block(struct dm_mintegrity *v, sector_t sector,
	bool prefetch)
{
	struct data_block *d;
	down_write(&v->hash_tree_semaphore);
	d = tree_search(&v->root_hash_node, sector);
	if (!d) {
		struct bio *bio;
		// Get from clean list if out of nodes to use
		if (v->num_hash_nodes >= 16384) {
			u8 *data;
			// TODO: make space if nothing in clean list
			d = list_entry(v->clean_hash_list.next, struct data_block, list);
			list_del(&d->list);
			rb_erase(&d->node, &v->root_hash_node);
			data = d->data;
			// In case of dirty writeback
			wait_for_completion(&d->event);
			memset(d, 0, sizeof(struct data_block));
			d->data = data;
		} else {
			// TODO: check allocation
			d = mempool_alloc(v->data_block_mempool, GFP_NOIO);
			memset(d, 0, sizeof(struct data_block));
			d->data = mempool_alloc(v->data_page_mempool, GFP_NOIO);
			v->num_hash_nodes++;
		}
		d->sector = sector;
		d->v = v;
		INIT_LIST_HEAD(&d->list);

		// Prefetch request doesn't actually hold data
		atomic_set(&(d->ref_count), prefetch ? 0 : 1);
		d->dirty = false;
		init_completion(&d->event);
		init_rwsem(&(d->lock));
		atomic_set(&(d->writers), 0);

		bio = &d->bio;
		memset(bio, 0, sizeof(struct bio));
		bio_init(bio);
		bio->bi_iter.bi_sector = sector << (v->dev_block_bits - SECTOR_SHIFT);
		bio->bi_bdev = v->dev->bdev;
		bio->bi_rw = READ;
		bio->bi_max_vecs = 1;
		bio->bi_io_vec = &d->bio_vec;

		bio->bi_end_io = mintegrity_hash_read_end_io;
		bio->bi_private = d;
		BUG_ON(!bio_add_page(bio, virt_to_page(d->data), 4096, 0));
		BUG_ON(!tree_insert(&v->root_hash_node, d));
		generic_make_request(bio);
	} else {
		// Remove from clean list if clean and being used
		if (!prefetch && atomic_inc_return(&d->ref_count) == 1 && !d->dirty) {
			list_del(&d->list);
		}
	}
	up_write(&v->hash_tree_semaphore);

	// Wait for read/write to finish
	if (!prefetch) {
		wait_for_completion(&d->event);
	}

	return d;
}

static void write_all_data_blocks(struct dm_mintegrity *v, bool flush) {
	struct rb_node *node;
	down_write(&v->data_tree_semaphore);
	node = rb_first(&v->root_data_node);
	while (node) {
		struct data_block *data = container_of(node, struct data_block, node);
		rb_erase(node, &v->root_data_node);
		generic_make_request(&(data->bio));
		node = rb_first(&v->root_data_node);
	}
	up_write(&v->data_tree_semaphore);
	if (flush) {
		blkdev_issue_flush(v->data_dev ? v->data_dev->bdev : v->dev->bdev,
			GFP_KERNEL, NULL);
	}
}

static void write_all_hash_blocks(struct dm_mintegrity *v, bool flush) {
	struct data_block *d;
	struct list_head *pos, *n;
	struct bio *bio;
	down_write(&v->hash_tree_semaphore);
	list_for_each_safe(pos, n, &v->dirty_hash_list) {
		d = container_of(pos, struct data_block, list);
		init_completion(&d->event);

		bio = &d->bio;
		memset(bio, 0, sizeof(struct bio));
		bio_init(bio);
		bio->bi_iter.bi_sector = d->sector << (v->dev_block_bits - SECTOR_SHIFT);
		bio->bi_bdev = v->dev->bdev;
		bio->bi_rw = WRITE;
		bio->bi_max_vecs = 1;
		bio->bi_io_vec = &d->bio_vec;

		bio->bi_end_io = mintegrity_hash_write_end_io;
		bio->bi_private = d;
		BUG_ON(!bio_add_page(bio, virt_to_page(d->data), 4096, 0));
		d->dirty = false;
		list_del(&d->list);

		if (atomic_read(&d->ref_count) == 0) {
			list_add_tail(&d->list, &v->clean_hash_list);
		}

		generic_make_request(&d->bio);
	}
	INIT_LIST_HEAD(&v->dirty_hash_list);
	up_write(&v->hash_tree_semaphore);
	if (flush) {
		blkdev_issue_flush(v->dev->bdev, GFP_KERNEL, NULL);
	}
}

static void delete_all_hash_blocks(struct dm_mintegrity *v) {
	struct rb_node *node;
	down_write(&v->hash_tree_semaphore);
	node = rb_first(&v->root_hash_node);
	while (node) {
		struct data_block *data = container_of(node, struct data_block, node);
		rb_erase(node, &v->root_hash_node);
		wait_for_completion(&data->event);
		mempool_free(data->data, v->data_page_mempool);
		mempool_free(data, v->data_block_mempool);
		node = rb_first(&v->root_hash_node);
	}
	INIT_LIST_HEAD(&v->clean_hash_list);
	INIT_LIST_HEAD(&v->dirty_hash_list);
	up_write(&v->hash_tree_semaphore);
}

struct dm_mintegrity_prefetch_work {
	struct work_struct work;
	struct dm_mintegrity *v;
	sector_t block;
	unsigned n_blocks;
};

static struct data_block **io_dm_buffers(struct dm_mintegrity *v,
	struct dm_mintegrity_io *io)
{
	return (struct data_block**)(io + 1);
}

static struct shash_desc *io_hash_desc(struct dm_mintegrity *v,
	struct dm_mintegrity_io *io)
{
	return (struct shash_desc *)(io_dm_buffers(v, io) + v->levels + 1);
}

static u8 *io_real_digest(struct dm_mintegrity *v, struct dm_mintegrity_io *io)
{
	return (u8*)(io_hash_desc(v, io)) + v->shash_descsize;
}

static u8 *io_want_digest(struct dm_mintegrity *v, struct dm_mintegrity_io *io)
{
	return io_real_digest(v, io) + v->digest_size;
}

/*
 * Translate input sector number to the sector number on the target device.
 */
static sector_t mintegrity_map_sector(struct dm_mintegrity *v,
	sector_t bi_sector)
{
	return v->data_start_shift + dm_target_offset(v->ti, bi_sector);
}

/*
 * Return hash position of a specified block at a specified tree level
 * (0 is the lowest level).
 * The lowest "hash_per_block_bits"-bits of the result denote hash position
 * inside a hash block. The remaining bits denote location of the hash block.
 */
static sector_t mintegrity_position_at_level(struct dm_mintegrity *v,
	sector_t block, int level)
{
	return block >> (level * v->hash_per_block_bits);
}

static void mintegrity_hash_at_level(struct dm_mintegrity *v, sector_t block,
	int level, sector_t *hash_block, unsigned *offset)
{
	sector_t position = mintegrity_position_at_level(v, block, level);
	unsigned idx;

	*hash_block = v->hash_level_block[level] + (position >> v->hash_per_block_bits);

	if (!offset)
		return;

	idx = position & ((1 << v->hash_per_block_bits) - 1);
	*offset = idx << (v->dev_block_bits - v->hash_per_block_bits);
}

static unsigned mintegrity_hash_buffer_offset(struct dm_mintegrity *v,
	sector_t block, int level)
{
	// TODO: document this
	sector_t position = mintegrity_position_at_level(v, block, level);
	unsigned idx;
	idx = position & ((1 << v->hash_per_block_bits) - 1);
	return idx << (v->dev_block_bits - v->hash_per_block_bits);
}

/*
 * Calculate hash of buffer and put it in io_real_digest
 */
static int mintegrity_buffer_hash(struct dm_mintegrity_io *io, const u8 *data,
	unsigned int len)
{
	struct dm_mintegrity *v = io->v;
	struct shash_desc *desc;
	int r;
	desc = io_hash_desc(v, io);
	desc->tfm = v->tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	r = crypto_shash_init(desc);
	if (unlikely(r < 0)) {
		DMERR("crypto_shash_init failed: %d", r);
		return r;
	}

	r = crypto_shash_update(desc, v->salt, v->salt_size);
	if (unlikely(r < 0)) {
		DMERR("crypto_shash_update failed: %d", r);
		return r;
	}

	r = crypto_shash_update(desc, data, len);
	if (unlikely(r < 0)) {
		DMERR("crypto_shash_update failed: %d", r);
		return r;
	}

	r = crypto_shash_final(desc, io_real_digest(v, io));
	if (unlikely(r < 0)) {
		DMERR("crypto_shash_final failed: %d", r);
		return r;
	}

	return 0;
}

/*
 * Calculate hmac of root buffer. Clobbers v->hmac_desc and v->hmac_digest
 * Doesn't use locks, also assumes v->root_digest is locked.
 * Result hmac in v->hmac_digest
 */
static int mintegrity_hmac_hash(struct dm_mintegrity *v)
{
	int r = crypto_shash_setkey(v->hmac_tfm, v->secret, v->secret_size);
	if (unlikely(r < 0)) {
		DMERR("crypto_shash_setkey failed: %d", r);
		return r;
	}

	r = crypto_shash_init(v->hmac_desc);
	if(unlikely(r < 0)){
		DMERR("crypto_shash_init failed: %d", r);
		return r;
	}

	r = crypto_shash_update(v->hmac_desc, v->root_digest, v->digest_size);
	if (unlikely(r < 0)) {
		DMERR("crypto_shash_update failed: %d", r);
		return r;
	}

	r = crypto_shash_final(v->hmac_desc, v->hmac_digest);
	if (unlikely(r < 0)) {
		DMERR("crypto_shash_final failed: %d", r);
		return r;
	}

	return 0;
}

static void mintegrity_journal_release(struct journal_block *j)
{
	struct dm_mintegrity *v = j->v;

	// Return data
	mempool_free(j->data, v->journal_page_mempool);
	memset(j, 0, sizeof(struct journal_block));
	mempool_free(j, v->journal_block_mempool);
}

static void mintegrity_journal_write_end_io(struct bio *bio, int error)
{
	struct journal_block *j = bio->bi_private;

	if (j->event) {
		complete_all(j->event);
	}

	mintegrity_journal_release(j);	
}

static void mintegrity_journal_read_end_io(struct bio *bio, int error)
{
	struct journal_block *j = bio->bi_private;

	if (j->event) {
		complete_all(j->event);
	}
}

static void mintegrity_do_journal_block_io(struct journal_block *j)
{
	generic_make_request(&j->bio);
}

static void mintegrity_init_journal_block(struct journal_block **jb,
	struct dm_mintegrity *v, sector_t sector, unsigned long rw,
	int size, bool setPages)
{
	int i;
	struct bio *bio;
	struct journal_block *j;
	*jb = j = mempool_alloc(v->journal_block_mempool, GFP_NOIO);
	j->data = mempool_alloc(v->journal_page_mempool, GFP_NOIO);
	BUG_ON(j->data == NULL);
	j->v = v;
	j->size = size;
	j->event = NULL;
	atomic_set(&j->available, size);
	atomic_set(&j->finished, 0);
 	bio = &j->bio;
	bio_init(bio);
	bio->bi_iter.bi_sector = sector << (v->dev_block_bits - SECTOR_SHIFT);
	bio->bi_bdev = v->dev->bdev;
	bio->bi_rw = rw;
	bio->bi_max_vecs = J_PAGE_CHUNK_SIZE;
	bio->bi_io_vec = j->bio_vec;
	bio->bi_end_io = (rw & WRITE ? mintegrity_journal_write_end_io
			: mintegrity_journal_read_end_io);
	bio->bi_private = j;
	if (setPages) {
		for (i = 0; i < min(J_PAGE_CHUNK_SIZE, size); i++) {
			BUG_ON(!bio_add_page(bio, virt_to_page(
				j->data + v->dev_block_bytes * i), v->dev_block_bytes, 0));
		}
	}
	sema_init(&j->sema, 0);
}

static void mintegrity_read_journal_block(struct journal_block **jb,
	struct dm_mintegrity *v, sector_t sector)
{
	struct completion event;
	mintegrity_init_journal_block(jb, v, sector, READ, 1, true);
	init_completion(&event);
	(*jb)->event = &event;
	mintegrity_do_journal_block_io(*jb);
	wait_for_completion(&event);
}

static void mintegrity_commit_journal(struct dm_mintegrity *v, bool flush)
{
	int i = 0;
	char *tag_ptr;
	sector_t sector;
	struct mint_journal_header mjh;
	struct mint_journal_block_tag tag;
	struct mint_journal_superblock *js = &v->j_sb_header;

	// Nothing to commit
	if (v->j_ds_fill == 0) {
		return;
	}

	// Journal block isn't fully used up
	if (v->jbs && atomic_read(&v->jbs->available) != 0) {
		// Use this spot for the descriptor block
		int which = 0;
		int toFree = 0;

		which = v->jbs->size - atomic_read(&v->jbs->available);
		toFree = (v->jbs->size - 1) - which;

		while (true) {
			volatile atomic_t *a = &ACCESS_ONCE(v->j_commit_outstanding);
			if (atomic_read(a) == 0) {
				break;
			}
			if (i != 0 && i % 100000000 == 0 ) {
				// printk(KERN_CRIT "1: millions: %d, %d",
				// 		i / 10000000, atomic_read(&v->j_commit_outstanding));
			}
			i++;
		}

		tag_ptr = v->j_ds_buffer->data + sizeof(struct mint_journal_header)
			+ (v->j_ds_fill - 1) * sizeof(struct mint_journal_block_tag);
		memcpy(&tag, tag_ptr, sizeof(struct mint_journal_block_tag));
		tag.options |= 4;
		memcpy(tag_ptr, &tag, sizeof(struct mint_journal_block_tag));

		BUG_ON(!bio_add_page(&v->jbs->bio, virt_to_page(
			v->jbs->data + v->dev_block_bytes * which), v->dev_block_bytes, 0));
		memcpy(v->jbs->data + (v->dev_block_bytes * which),
			v->j_ds_buffer->data, v->dev_block_bytes);
		mintegrity_do_journal_block_io(v->jbs);

		v->jbs = NULL;
		v->j_ds_buffer->event = NULL;
		mintegrity_journal_write_end_io(&v->j_ds_buffer->bio, 0);

		if (toFree) {
			atomic_add(-toFree, &v->j_fill);
			if (atomic_read(&v->j_fill) < 0) {
				printk(KERN_CRIT "j_fill < 0");
			}
			// printk("New fill: %d\n", atomic_read(&v->j_fill));
			if (js->tail < toFree) {
				js->tail = v->journal_blocks - 1 - (toFree - js->tail);
			} else {
				js->tail -= toFree;
			}
		}
	} else {
		while (true) {
			volatile atomic_t *a = &ACCESS_ONCE(v->j_commit_outstanding);
			if (atomic_read(a) == 0) {
				break;
			}
			if (i != 0 && i % 100000000 == 0 ) {
				// printk(KERN_CRIT "2: millions: %d, %d",
				// 		i / 10000000, atomic_read(&v->j_commit_outstanding));
			}
			i++;
		}

		tag_ptr = v->j_ds_buffer->data + sizeof(struct mint_journal_header)
			+ (v->j_ds_fill - 1) * sizeof(struct mint_journal_block_tag);
		memcpy(&tag, tag_ptr, sizeof(struct mint_journal_block_tag));
		tag.options |= 4;
		memcpy(tag_ptr, &tag, sizeof(struct mint_journal_block_tag));

		sector = v->journal_start + ((js->tail) % (v->journal_blocks - 1));
		js->tail = (js->tail + 1) % (v->journal_blocks - 1);
		atomic_add(1, &v->j_fill);

		v->j_ds_buffer->bio.bi_rw = WRITE;
		v->j_ds_buffer->bio.bi_iter.bi_sector = sector << (v->dev_block_bits - SECTOR_SHIFT);
		BUG_ON(!bio_add_page(&v->j_ds_buffer->bio,
			virt_to_page(v->j_ds_buffer->data), v->dev_block_bytes, 0));

		mintegrity_do_journal_block_io(v->j_ds_buffer);
	}

	if (flush) {
		struct completion event;
		struct journal_block *jb;
		struct mint_journal_superblock *js = &v->j_sb_header;

		mintegrity_init_journal_block(&jb, v, v->journal_start + v->journal_blocks - 1,
				REQ_FUA | REQ_FLUSH | WRITE_SYNC | WRITE, 1, true);

		js->tail = cpu_to_le32(js->tail);
		js->state = 1;
		BUG_ON(!jb->data);

		memcpy(jb->data, js, sizeof(struct mint_journal_superblock));
		js->tail = le32_to_cpu(js->tail);

		memcpy(jb->data + sizeof(struct mint_journal_superblock),
				v->hmac_digest, v->hmac_digest_size);

		// Calculate hmac
		mintegrity_hmac_hash(v);
		memcpy(jb->data + sizeof(struct mint_journal_superblock) + v->hmac_digest_size,
				v->hmac_digest, v->hmac_digest_size);

		init_completion(&event);
		jb->event = &event;
		mintegrity_do_journal_block_io(jb);
		wait_for_completion(&event);
		if (v->two_disks) {
			write_all_data_blocks(v, false);
		}
	}

	v->j_ds_fill = 0;


	// Get new desciptor block
	sector = v->journal_start + ((js->tail) % (v->journal_blocks - 1));
	mintegrity_init_journal_block(&v->j_ds_buffer, v, sector, WRITE_SYNC, 1, false);
	mjh.magic = cpu_to_le32(MJ_MAGIC);
	mjh.type = cpu_to_le32(TYPE_MJDB);
	memset(v->j_ds_buffer->data, 0, v->dev_block_bytes);
	memcpy(v->j_ds_buffer->data, &mjh, sizeof(struct mint_journal_header));
}

static void mintegrity_add_buffer_to_journal(struct dm_mintegrity *v,
	sector_t sector, struct data_block **data_buffers,
	struct journal_block *journal_buffer, int error, char *tag_ptr,
	int which)
{
	int i;
	char magic[4] = {0x59, 0x4c, 0x49, 0x4c};
	struct mint_journal_block_tag tag = {
		cpu_to_le32(sector),
		cpu_to_le32(sector >> 32),
		0
	};

	if (error) {
		DMERR("Add buffers error!");
	}

	if (data_buffers) {
		for (i = 0; i < v->levels; i++) {
			if (!data_buffers[i]) {
				continue;
			}
			hash_block_mark_dirty(data_buffers[i]);
			hash_block_release(data_buffers[i]);
		}
	}

	if (unlikely(!memcmp(journal_buffer->data + (v->dev_block_bytes * which),
		magic, 4))) {
		tag.options |= 2;
		memset(journal_buffer->data + (v->dev_block_bytes * which), 0, 4);
	}
	if (unlikely(error)) {
		tag.options |= 1;
	}
	memcpy(tag_ptr, &tag, sizeof(struct mint_journal_block_tag));

	i = journal_buffer->size;
	if (atomic_inc_return(&journal_buffer->finished) == i) {
		mintegrity_do_journal_block_io(journal_buffer);
	}
	atomic_dec(&v->j_commit_outstanding);
}

static void mintegrity_checkpoint_journal(struct dm_mintegrity *v)
{
	struct mint_journal_superblock *js = &v->j_sb_header;

	write_all_hash_blocks(v, false);
	write_all_data_blocks(v, true);
	if (v->two_disks) {
		blkdev_issue_flush(v->dev->bdev, GFP_KERNEL, NULL);
	}
	atomic_set(&v->j_fill, 0);
	js->tail = 0;
}

static int mintegrity_get_journal_buffer(struct dm_mintegrity *v,
	struct journal_block **buffer, uint8_t **tag)
{
	int r;
	struct mint_journal_superblock *js = &v->j_sb_header;

	// Lock journal
	down_write(&v->j_lock);

	// Check if we have space in the descriptor block for a tag
	if (v->j_ds_fill == v->j_ds_max) {
		// We don't lets get a new one
		mintegrity_commit_journal(v, false);
	}

	// NO jbs or current one is full
	if (v->jbs == NULL || atomic_read(&v->jbs->available) == 0) {
		sector_t sector;
		int size = J_PAGE_CHUNK_SIZE;

		// Check for space - need blocks chunk + commit block
		if (atomic_read(&v->j_fill) + 1 + J_PAGE_CHUNK_SIZE >= v->journal_blocks - 1) {
			// Make space in journal
			mintegrity_commit_journal(v, true);
			mintegrity_checkpoint_journal(v);
		}

		// Not enough for a full chunk
		if (v->j_ds_fill + J_PAGE_CHUNK_SIZE >= v->j_ds_max) {
			size = v->j_ds_max - v->j_ds_fill;
		}

		// Get new one
		sector = (v->journal_start + ((js->tail) % (v->journal_blocks - 1)));
		mintegrity_init_journal_block(&v->jbs, v, sector, WRITE, size, false);
		v->jbs->hasExtra = false;

		// Increment tail position
		js->tail = (js->tail + size) % (v->journal_blocks - 1);
		atomic_add(size, &v->j_fill);

		atomic_set(&v->jbs->available, size);
		atomic_set(&v->jbs->finished, 0);
	}

	*buffer = v->jbs;
	r = (v->jbs->size - 1) - atomic_dec_return(&v->jbs->available);
	BUG_ON(!bio_add_page(&v->jbs->bio, virt_to_page(
		v->jbs->data + v->dev_block_bytes * r), v->dev_block_bytes, 0));
	if (r == v->jbs->size - 1) {
		v->jbs = NULL;
	}

	// struct mint_journal_block_tag location in descriptor block
	*tag = v->j_ds_buffer->data + sizeof(struct mint_journal_header)
		+ v->j_ds_fill * sizeof(struct mint_journal_block_tag);
	// Increment descriptor block fill
	v->j_ds_fill++;

	atomic_inc(&v->j_commit_outstanding);

	// Unlock journal
	up_write(&v->j_lock);
	return r;
}

static void mintegrity_unmount_journal(struct dm_mintegrity *v)
{
	struct journal_block *jb;
	struct mint_journal_superblock *js = &v->j_sb_header;
	struct completion event;

	mintegrity_commit_journal(v, true);
	mintegrity_checkpoint_journal(v);
	mintegrity_hmac_hash(v);

	js->tail = 0;
	js->state = 0;

	mintegrity_init_journal_block(&jb, v, v->journal_start + v->journal_blocks - 1,
		WRITE, 1, true);
	memcpy(jb->data, js, sizeof(struct mint_journal_superblock));
	memcpy(jb->data + sizeof(struct mint_journal_superblock), v->hmac_digest,
		v->hmac_digest_size);
	memcpy(jb->data + sizeof(struct mint_journal_superblock) + v->hmac_digest_size,
		v->hmac_digest, v->hmac_digest_size);

	init_completion(&event);
	jb->event = &event;
	mintegrity_do_journal_block_io(jb);
	wait_for_completion(&event);
}

static int mintegrity_recover_journal(struct dm_mintegrity *v)
{
	struct dm_mintegrity_io *io;
	struct completion event;
	struct mint_journal_header mjh;
	struct journal_block *jb;
	struct mint_journal_superblock *js = &v->j_sb_header;
	char root_digest[v->digest_size];

	js->tail = 0;
	js->state = 0;

	// Max number of block tags in one journal descriptor block
	v->j_ds_max = (v->dev_block_bytes - sizeof(struct mint_journal_header)) /
		sizeof(struct mint_journal_block_tag);
	v->j_ds_max = (v->j_ds_max) - (v->j_ds_max % J_PAGE_CHUNK_SIZE) - 1;

	v->journal_block_mempool = mempool_create_kmalloc_pool(4000, sizeof(struct journal_block));
	v->journal_page_mempool = mempool_create(2000, __get_free_pages, free_pages, J_PAGE_ORDER_SIZE);
	v->data_block_mempool = mempool_create_kmalloc_pool(25000, sizeof(struct data_block));
	v->data_page_mempool = mempool_create(25000, __get_free_pages, free_pages, 0);

	// Allocate io struct for usage
	io = kzalloc(v->ti->per_bio_data_size, GFP_KERNEL);
	if (!io) {
		DMERR("Failed to allocate memory for temp io");
		return -ENOMEM;
	}
	io->v = v;

	// Read superblock
	mintegrity_read_journal_block(&jb, v, v->journal_start + v->journal_blocks - 1);
	memcpy(js, jb->data, sizeof(struct mint_journal_superblock));
	js->tail = le32_to_cpu(js->tail);
	DMINFO("JS tail: %ld, state: %d", js->tail, js->state);
	// Dirty
	if (js->state) {
		sector_t sector_start, sector_end;

		DMINFO("Recoverying journal...");

		// Back up root digest
		memcpy(root_digest, v->root_digest, v->digest_size);

		// Replay descriptor blocks until tail
		sector_start = v->journal_start;
		sector_end = v->journal_start + js->tail;
		while (true) {
			int i, level;
			bool found;
			struct journal_block *desc_jb, *data_jb;
			sector_t sector_descriptor = sector_start + 1;
			found = false;
			while (sector_descriptor <= sector_end) {
				mintegrity_read_journal_block(&desc_jb, v, sector_descriptor);
				memcpy(&mjh, desc_jb->data, sizeof(struct mint_journal_header));
				mjh.magic = le32_to_cpu(mjh.magic);
				mjh.type = le32_to_cpu(mjh.type);
				if (mjh.magic == MJ_MAGIC && mjh.type == TYPE_MJDB) {
					found = true;
					break;
				}
				mintegrity_journal_release(desc_jb);
				sector_descriptor++;
			}
			// Didn't find another descriptor
			if (!found) {
				break;
			}
			DMINFO("Descriptor...");

			// Loop through descriptor tags
			for (i = 0; i < v->j_ds_max; i++) {
				int r;
				struct data_block *d, *h;
				uint32_t options;
				sector_t data_sector;
				struct mint_journal_block_tag *tag = (struct mint_journal_block_tag*)
						(desc_jb->data + sizeof(struct mint_journal_header)
							+ i * sizeof(struct mint_journal_block_tag));
				data_sector = le32_to_cpu(tag->high);
				data_sector = (data_sector << 32) | le32_to_cpu(tag->low);
				options = le32_to_cpu(tag->options);
				if (options & 1) {
					// Last one
					if (options & 4) {
						break;
					}
					// Skip this one
					continue;
				}

				DMINFO("Write data to: %ld -> %ld",
						data_sector, data_sector + v->data_start);

				// Read data to write
				mintegrity_read_journal_block(&data_jb, v, sector_start + i);

				// Add escaped magic sequence
				if (options & 2) {
					data_jb->data[0] = 0x59;
					data_jb->data[1] = 0x4c;
					data_jb->data[2] = 0x49;
					data_jb->data[3] = 0x4c;
				}

				// Get destination data
				d = get_data_block(v, data_sector + v->data_start, false);
				memcpy(d->data, data_jb->data, v->dev_block_bytes);
				mintegrity_journal_release(data_jb);

				r = mintegrity_buffer_hash(io, d->data, v->dev_block_bytes);
				data_block_release(d);
				if (r) {
					mintegrity_journal_release(desc_jb);
					mintegrity_journal_release(jb);
					kfree(io);
					return -EINVAL;
				}

				// Write things bottom up
				for (level = 0; level < v->levels; level++) {
					sector_t hash_block;
					unsigned offset;
					mintegrity_hash_at_level(v, data_sector, level, &hash_block, &offset);
					h = get_hash_block(v, hash_block, false);
					memcpy(h->data + offset, io_real_digest(v, io), v->digest_size);
					r = mintegrity_buffer_hash(io, h->data, v->dev_block_bytes);
					hash_block_release(h);
					if (r) {
						mintegrity_journal_release(desc_jb);
						mintegrity_journal_release(jb);
						kfree(io);
						return -EINVAL;
					}
				}

				// Copy into root
				memcpy(v->root_digest, io_real_digest(v, io), v->digest_size);

				// Last tag
				if (options & 4) {
					break;
				}
			}
			mintegrity_journal_release(desc_jb);
			sector_start = sector_descriptor;
		}

		// Compute new hmac
		mintegrity_hmac_hash(v);

		if (memcmp(v->hmac_digest, jb->data
					+ sizeof(struct mint_journal_superblock)
					+ v->hmac_digest_size, v->hmac_digest_size)) {
			DMWARN("Recovered hmac doesn't match!");
			// New hmac doesn't match - abort everything
			delete_all_hash_blocks(v);

			// Restore previous
			memcpy(v->root_digest, root_digest, v->digest_size);

			// Compute original hmac
			mintegrity_hmac_hash(v);

			print_hex_dump(KERN_CRIT, "RT: ", DUMP_PREFIX_NONE, 4, v->digest_size, v->root_digest, 32, false);
			print_hex_dump(KERN_CRIT, "H : ", DUMP_PREFIX_NONE, 4, v->hmac_digest_size, v->hmac_digest, 32, false);

			if (memcmp(v->hmac_digest, jb->data
						+ sizeof(struct mint_journal_superblock),
						v->hmac_digest_size)) {
				DMWARN("Original hmac doesn't match!");
				// Original doesn't match - print error message
				// Will try to read as best as possible
			}
		} else {
			DMINFO("Recovered hmac matches!");
			// New hmac matches! - write everything out
			write_all_hash_blocks(v, true);
			write_all_data_blocks(v, true);
		}
		// Write out clean journal end
		mintegrity_journal_release(jb);
		js->tail = 0;
		js->state = 0;
		mintegrity_init_journal_block(&jb, v,
			v->journal_start + v->journal_blocks - 1, WRITE_SYNC | WRITE_FLUSH_FUA,
			1, true);
		memcpy(jb->data, js, sizeof(struct mint_journal_superblock));
		memcpy(jb->data + sizeof(struct mint_journal_superblock),
			v->hmac_digest, v->hmac_digest_size);
		memcpy(jb->data + sizeof(struct mint_journal_superblock) + v->hmac_digest_size,
			v->hmac_digest, v->hmac_digest_size);
		init_completion(&event);
		jb->event = &event;
		mintegrity_do_journal_block_io(jb);
		wait_for_completion(&event);
	} else {
		struct data_block *h;
		sector_t hash_block;
		unsigned offset;
		printk(KERN_CRIT "HERE 10\n");

		mintegrity_hash_at_level(v, 0, v->levels - 1, &hash_block, &offset);
		printk(KERN_CRIT "HERE 11\n");
		h = get_hash_block(v, hash_block, false);
		printk(KERN_CRIT "HERE 12\n");
		mintegrity_buffer_hash(io, h->data, v->dev_block_bytes);

		if (memcmp(v->root_digest, io_real_digest(v, io), v->digest_size)) {
			DMWARN("Root node doesn't match!");

			// Back up root digest
			memcpy(root_digest, v->root_digest, v->digest_size);

			memcpy(v->root_digest, io_real_digest(v, io), v->digest_size);
			mintegrity_hmac_hash(v);

			if (memcmp(v->hmac_digest, jb->data + sizeof(struct mint_journal_superblock), v->hmac_digest_size)) {
				DMWARN("Recovery hmac doesn't match either!");
				memcpy(v->root_digest, root_digest, v->digest_size);
				mintegrity_hmac_hash(v);
			}
		}
		hash_block_release(h);
	}

	kfree(io);

	// Number of blocks necessary per transaction - packed digests + data block
	v->j_bpt = 1;
	v->j_ds_fill = 0;

	// Need at least one transaction + superblock + descriptor + commit
	if (v->journal_blocks < v->j_bpt + 3) {
		return -EINVAL;
	}

	// New descriptor block
	mintegrity_init_journal_block(&v->j_ds_buffer, v, (v->journal_start),
		WRITE, 1, false);
	// Copy descriptor header
	mjh.magic = cpu_to_le32(MJ_MAGIC);
	mjh.type = cpu_to_le32(TYPE_MJDB);
	memset(v->j_ds_buffer->data, 0, v->dev_block_bytes);
	memcpy(v->j_ds_buffer->data, &mjh, sizeof(struct mint_journal_header));

	js->tail = 0;
	atomic_set(&v->j_fill, 0);

	atomic_set(&v->j_commit_outstanding, 0);
	atomic_set(&v->jbs_available, 0);
	atomic_set(&v->jbs_finished, 0);
	v->jbs = NULL;

	return 0;
}

/*
 * Verify hash of a metadata block pertaining to the specified data block
 * ("block" argument) at a specified level ("level" argument).
 *
 * On successful return, io_want_digest(v, io) contains the hash value for
 * a lower tree level or for the data block (if we're at the lowest leve).
 *
 * If "skip_unverified" is true, unverified buffer is skipped and 1 is returned.
 * If "skip_unverified" is false, unverified buffer is hashed and verified
 * against current value of io_want_digest(v, io).
 *
 * If dmb is not NULL, then the buffer, data and offset are stored into that
 * pointer and the dm-bufio buffer is NOT RELEASED
 */
static int mintegrity_verify_level(struct dm_mintegrity_io *io, sector_t block,
	int level, bool skip_unverified, bool first, struct data_block **dmb)
{
	struct dm_mintegrity *v = io->v;
	struct data_block *d;
	int r;
	sector_t hash_block;
	unsigned offset;

	mintegrity_hash_at_level(v, block, level, &hash_block, &offset);

	d = get_hash_block(v, hash_block, false);

	if (!atomic_read(&d->hash_verified)) {
		u8 *result;

		if (skip_unverified) {
			r = 1;
			goto release_ret_r;
		}

		r = mintegrity_buffer_hash(io, d->data, v->dev_block_bytes);
		if (unlikely(r != 0)) {
			goto release_ret_r;
		}

		result = io_real_digest(v, io);

		if (!atomic_read(&d->hash_verified)
				&& unlikely(memcmp(result, io_want_digest(v, io), v->digest_size))) {
			// Retry once in case of write race condition
			if (first) {
				hash_block_release(d);
				memcpy(io_want_digest(v, io), io->previous_hash, v->digest_size);
				return mintegrity_verify_level(io, block, level,
					skip_unverified, false, dmb);
			} else {
				DMERR_LIMIT("metadata block %llu is corrupted",
					(unsigned long long)hash_block);
				v->hash_failed = 1;
				r = -EIO;
				goto release_ret_r;
			}
		} else {
			atomic_set(&d->hash_verified, 1);
		}
	}

	memcpy(io_want_digest(v, io), d->data + offset, v->digest_size);
	io->previous_hash = d->data + offset;

	// Return back the whole block we read and verified
	if (dmb) {
		*dmb = d;
	} else {
		hash_block_release(d);
	}

	return 0;

	release_ret_r:
	hash_block_release(d);

	return r;
}

/*
 * Verify one "dm_mintegrity_io" structure.
 */
static int mintegrity_verify_read_io(struct dm_mintegrity_io *io)
{
	struct dm_mintegrity *v = io->v;
	struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_bio_data_size);
	unsigned b;
	int i, j, r;
	struct data_block **dm_buffers = io_dm_buffers(v, io);
	struct shash_desc *desc;
	bool skip_chain = false;

	for (b = 0; b < io->n_blocks; b++) {
		u8 *result;
		unsigned todo;
		sector_t data_sector;
		data_sector = io->block + b;
		skip_chain = false;

		if (likely(v->levels)) {
			/*
			 * First, we try to get the requested hash for
			 * the current block. If the hash block itself is
			 * verified, zero is returned. If it isn't, this
			 * function returns 0 and we fall back to whole
			 * chain verification.
			 */
			int r = mintegrity_verify_level(io, data_sector, 0, true, true, NULL);
			if (likely(!r)) {
				skip_chain = true;
				goto test_block_hash;
			}
			if (r < 0)
				return r;
		}

		memcpy(io_want_digest(v, io), v->root_digest, v->digest_size);

		// Race condition fix
		io->previous_hash = v->root_digest;

		for (i = v->levels - 1; i >= 0; i--) {
			int r = mintegrity_verify_level(io, data_sector, i, false, true,
				dm_buffers + i);
			if (unlikely(r)) {
				for (j = v->levels - 1; j > i; j--) {
					hash_block_release(dm_buffers[j]);
				}
				return r;
			}
		}

	test_block_hash:
		desc = io_hash_desc(v, io);
		desc->tfm = v->tfm;
		desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
		r = crypto_shash_init(desc);
		if (r < 0) {
			DMERR("crypto_shash_init failed: %d", r);
			goto release_ret_r;
		}
		r = crypto_shash_update(desc, v->salt, v->salt_size);
		if (r < 0) {
			DMERR("crypto_shash_update failed: %d", r);
			goto release_ret_r;
		}

		todo = 1 << v->dev_block_bits;
		do {
			u8 *page;
			unsigned len;
			struct bio_vec bv = bio_iter_iovec(bio, io->iter);

			page = kmap_atomic(bv.bv_page);
			len = bv.bv_len;
			if (likely(len >= todo)) {
				len = todo;
			}
			r = crypto_shash_update(desc, page + bv.bv_offset, len);
			kunmap_atomic(page);

			if (r < 0) {
				DMERR("crypto_shash_update failed: %d", r);
				goto release_ret_r;
			}

			bio_advance_iter(bio, &io->iter, len);
			todo -= len;
		} while (todo);

		result = io_real_digest(v, io);
		r = crypto_shash_final(desc, result);
		if (r < 0) {
			DMERR("crypto_shash_final failed: %d", r);
			goto release_ret_r;
		}

		if (unlikely(memcmp(result, io_want_digest(v, io), v->digest_size))) {
			// If zero digest is enabled and it matches the wanted digest
			if (v->zero_digest && !memcmp(io_want_digest(v, io), v->zero_digest, v->digest_size)) {
				// Zero it out
				todo = 1 << v->dev_block_bits;
				// FIXME: hack to reset iterator
				io->iter.bi_sector -= (todo >> 9);
				io->iter.bi_size += todo;
				io->iter.bi_idx--;
				io->iter.bi_bvec_done = 0;

				do {
					u8 *page;
					unsigned len;
					struct bio_vec bv = bio_iter_iovec(bio, io->iter);

					page = kmap_atomic(bv.bv_page);
					len = bv.bv_len;
					if (likely(len >= todo)) {
						len = todo;
					}

					memset(page + bv.bv_offset, 0, len);
					kunmap_atomic(page);

					bio_advance_iter(bio, &io->iter, len);
					todo -= len;
				} while (todo);
			} else {
				DMERR_LIMIT("data block %llu is corrupted",
					(unsigned long long)(io->block + b));
				v->hash_failed = 1;
				r = -EIO;
				goto release_ret_r;
			}
		}
	}
	if (!skip_chain) {
		for (i = v->levels - 1; i >= 0; i--) {
			hash_block_release(dm_buffers[i]);
		}
	}

	return 0;

	release_ret_r:
		if (!skip_chain) {
			for (i = v->levels - 1; i >= 0; i--) {
				hash_block_release(dm_buffers[i]);
			}
		}
		return r;
}

static int mintegrity_verify_write_io(struct dm_mintegrity_io *io)
{
	unsigned b;
	int i, j;
	struct data_block *data_block, *d;
	struct dm_mintegrity *v = io->v;
	struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_bio_data_size);

	for (b = 0; b < io->n_blocks; b++) {
		int r;
		u8 *result;
		u8 *data;
		unsigned todo;
		uint8_t *tag = NULL;

		int which;

		// Pointers for modified hash and data block
		struct data_block **dm_buffers = io_dm_buffers(v, io);
		// Pointer for jounral entry
		struct journal_block *j_buffer;
		sector_t sector = io->block + b;

		// Set all to NULL for possible cleanup
		for (i = 0; i < v->levels + 1; i++) {
			dm_buffers[i] = NULL;
		}

		// Get journal block
		if ((which = mintegrity_get_journal_buffer(v, &j_buffer, &tag)) < 0) {
			// Safe to return because nothing needs to be cleaned up here
			return -EIO;
		}

		// The io digest we want is the root
		memcpy(io_want_digest(v, io), v->root_digest, v->digest_size);

		// Read levels, TOP DOWN and compare to io want, which is set after
		// every successive read
		// FIXME: on demand memory, fail gracefully
		io->previous_hash = v->root_digest;

		for (i = v->levels - 1; i >= 0; i--) {
			r = mintegrity_verify_level(io, sector, i, false, true, dm_buffers + i);
			if (unlikely(r != 0)) {
				DMERR("failed write read layers");
				for (j = v->levels - 1; j > i; j--) {
					atomic_dec(&dm_buffers[j]->writers);
					hash_block_release(dm_buffers[j]);
				}
				mintegrity_add_buffer_to_journal(v, sector, NULL, j_buffer,
					-EIO, tag, which);
				return -EIO;
			}
			atomic_inc(&dm_buffers[i]->writers);
		}
		// Get ready to write to disk
		// FIXME: on demand memory, fail gracefully
		data_block = get_data_block(v, sector + v->data_start, false);
		data = data_block->data;

		// Copy from bio vector to journal data buffer
		todo = v->dev_block_bytes;
		do {
			u8 *page;
			unsigned len;
			struct bio_vec bv = bio_iter_iovec(bio, io->iter);

			page = kmap_atomic(bv.bv_page);
			len = bv.bv_len;
			if (likely(len >= todo)) {
				len = todo;
			}

			memcpy(data + v->dev_block_bytes - todo, page + bv.bv_offset, len);
			kunmap_atomic(page);

			bio_advance_iter(bio, &io->iter, len);
			todo -= len;
		} while (todo);

		// Copy into journal
		memcpy(j_buffer->data + (v->dev_block_bytes * which), data,
			v->dev_block_bytes);

		// Hash new data
		r = mintegrity_buffer_hash(io, data, v->dev_block_bytes);
		if (unlikely(r != 0)) {
			goto bad;
		}
		result = io_real_digest(v, io);

		// Copy data hash into first level
		memcpy(dm_buffers[0]->data +
			mintegrity_hash_buffer_offset(v, sector, 0),
			result, v->digest_size);

		// Write things back bottom up
		for (i = 1; i < v->levels; i++) {
			d = dm_buffers[i - 1];
			if (atomic_dec_return(&d->writers) == 0) {
				// Acquire lock - this means the block is not being written out
				// or has finished writing out
				down_write(&d->lock);
				// Calculate hash for level below
				r = mintegrity_buffer_hash(io, d->data, v->dev_block_bytes);
				if (unlikely(r < 0)) {
					DMERR("failed to calculate write buffer hash for level");
					goto bad;
				}
				result = io_real_digest(v, io);
				// Copy hash into current level
				memcpy(dm_buffers[i]->data +
					mintegrity_hash_buffer_offset(v, sector, i), result,
					v->digest_size);
				up_write(&d->lock);
			}
		}

		d = dm_buffers[v->levels - 1];
		if (atomic_dec_return(&d->writers) == 0) {
			down_write(&d->lock);
			// Update root merkle tree hashes
			r = mintegrity_buffer_hash(io, d->data, v->dev_block_bytes);
			if (unlikely(r < 0)) {
				DMERR("failed to calculate write buffer hash for level");
				goto bad;
			}
			result = io_real_digest(v, io);
			memcpy(v->root_digest, result, v->digest_size);
			up_write(&d->lock);
		}

		data_block_release(data_block);
		mintegrity_add_buffer_to_journal(v, sector, dm_buffers, j_buffer,
			0, tag, which);
		continue;

	bad:
		DMERR("ERROR at end of write work");
		mintegrity_add_buffer_to_journal(v, sector, dm_buffers, j_buffer,
			-EIO, tag, which);
		return -EIO;
	}
	// Finished!
	return 0;
}

static void mintegrity_read_work(struct work_struct *w)
{
	int error;
	struct dm_mintegrity_io *io = container_of(w, struct dm_mintegrity_io, work);
	struct dm_mintegrity *v = io->v;
	struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_bio_data_size);

	error = mintegrity_verify_read_io(io);

	up(&v->request_limit);
	bio_endio_nodec(bio, error);
}

static void mintegrity_read_end_io(struct bio *bio, int error)
{
	struct dm_mintegrity_io *io = bio->bi_private;

	bio->bi_iter.bi_sector = bio->bi_iter.bi_sector
			- (io->v->data_start << (io->v->dev_block_bits - SECTOR_SHIFT));
	bio->bi_end_io = io->orig_bi_end_io;
	bio->bi_private = io->orig_bi_private;

	if (error) {
		up(&io->v->request_limit);
		bio_endio_nodec(bio, error);
		return;
	}

	INIT_WORK(&(io->work), mintegrity_read_work);
	queue_work(io->v->workqueue, &io->work);
}

static void mintegrity_write_work(struct work_struct *w)
{
	struct dm_mintegrity_io *io;
	struct bio *bio;
	int error;
	io = container_of(w, struct dm_mintegrity_io, work);
	bio = dm_bio_from_per_bio_data(io, io->v->ti->per_bio_data_size);

	error = mintegrity_verify_write_io(io);

	if (unlikely(bio->bi_rw & (REQ_FLUSH | REQ_FUA))) {
		down_write(&io->v->j_lock);
		mintegrity_commit_journal(io->v, true);
		up_write(&io->v->j_lock);
	}

	up(&io->v->request_limit);
	bio_endio(bio, error);
}

/*
 * Prefetch buffers for the specified io.
 * The root buffer is not prefetched, it is assumed that it will be cached
 * all the time.
 */
static void mintegrity_prefetch_io(struct work_struct *work)
{
	struct dm_mintegrity_prefetch_work *pw =
		container_of(work, struct dm_mintegrity_prefetch_work, work);
	struct dm_mintegrity *v = pw->v;
	int i;
	sector_t s;

	for (i = v->levels - 2; i >= 0; i--) {
		sector_t hash_block_start;
		sector_t hash_block_end;
		mintegrity_hash_at_level(v, pw->block, i, &hash_block_start, NULL);
		mintegrity_hash_at_level(v, pw->block + pw->n_blocks - 1, i,
			&hash_block_end, NULL);
		if (!i) {
			unsigned cluster = ACCESS_ONCE(dm_mintegrity_prefetch_cluster);

			cluster >>= v->dev_block_bits;
			if (unlikely(!cluster))
				goto no_prefetch_cluster;

			if (unlikely(cluster & (cluster - 1)))
				cluster = 1 << __fls(cluster);

			hash_block_start &= ~(sector_t)(cluster - 1);
			hash_block_end |= cluster - 1;
			if (unlikely(hash_block_end >= v->hash_blocks))
				hash_block_end = v->hash_blocks - 1;
		}
	no_prefetch_cluster:
		for (s = hash_block_start; s < hash_block_end - hash_block_start + 1; s++) {
			get_hash_block(v, s, true);
		}
	}

	kfree(pw);
}

static void mintegrity_submit_prefetch(struct dm_mintegrity *v,
	struct dm_mintegrity_io *io)
{
	struct dm_mintegrity_prefetch_work *pw;

	pw = kmalloc(sizeof(struct dm_mintegrity_prefetch_work),
		GFP_NOIO | __GFP_NORETRY | __GFP_NOMEMALLOC | __GFP_NOWARN);

	if (!pw)
		return;

	INIT_WORK(&pw->work, mintegrity_prefetch_io);
	pw->v = v;
	pw->block = io->block;
	pw->n_blocks = io->n_blocks;
	queue_work(v->workqueue, &pw->work);
}

/*
 * Bio map function. It allocates dm_mintegrity_io structure and bio vector and
 * fills them. Then it issues prefetches and the I/O.
 */
static int mintegrity_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_mintegrity *v = ti->private;
	struct dm_mintegrity_io *io;

	// Block device
	bio->bi_bdev = (v->data_dev ? v->data_dev->bdev : v->dev->bdev);
	bio->bi_iter.bi_sector = mintegrity_map_sector(v, bio->bi_iter.bi_sector);

	if (((unsigned)bio->bi_iter.bi_sector | bio_sectors(bio)) &
	    ((1 << (v->dev_block_bits - SECTOR_SHIFT)) - 1)) {
		DMERR_LIMIT("unaligned io");
		return -EIO;
	}

	if (bio_end_sector(bio) >>
	    (v->dev_block_bits - SECTOR_SHIFT) > v->data_blocks) {
		DMERR_LIMIT("io out of range");
		return -EIO;
	}

	// For read only mode
	// if (bio_data_dir(bio) == WRITE) {
	// 	return -EIO;
	// }

	if (bio_data_dir(bio) == WRITE || bio_data_dir(bio) == READ) {
		// Common setup
		io = dm_per_bio_data(bio, ti->per_bio_data_size);
		io->v = v;
		io->block = bio->bi_iter.bi_sector >> (v->dev_block_bits - SECTOR_SHIFT);
		io->n_blocks = bio->bi_iter.bi_size >> v->dev_block_bits;
		io->iter = bio->bi_iter;

		// Limit the number of write requests
		down(&v->request_limit);

		// Prefetch blocks
		mintegrity_submit_prefetch(v, io);

		if (bio_data_dir(bio) == WRITE) {
			INIT_WORK(&(io->work), mintegrity_write_work);
			queue_work(io->v->workqueue, &io->work);
		} else {
			// Check local cache for non-written out blocks
			// FIXME: multiple block support
			struct data_block *b = get_data_block(v, io->block + v->data_start, true);
			if (b) {
				unsigned int todo = 4096;
				unsigned long flags;
				struct bio_vec bv;
				struct bvec_iter iter;
				bio_for_each_segment(bv, bio, iter) {
					char *data = bvec_kmap_irq(&bv, &flags);
					memcpy(data, b->data + v->dev_block_bytes - todo, bv.bv_len);
					flush_dcache_page(bv.bv_page);
					bvec_kunmap_irq(data, &flags);
				}

				data_block_release(b);
				up(&v->request_limit);
				bio_endio(bio, 0);
			} else {
				// Send out read request
				bio->bi_iter.bi_sector = bio->bi_iter.bi_sector
						+ (v->data_start << (v->dev_block_bits - SECTOR_SHIFT));

				io->orig_bi_end_io = bio->bi_end_io;
				io->orig_bi_private = bio->bi_private;
				bio->bi_end_io = mintegrity_read_end_io;
				bio->bi_private = io;
				generic_make_request(bio);
			}
		}
	}

	return DM_MAPIO_SUBMITTED;
}

/*
 * Status: V (valid) or C (corruption found)
 */
static void mintegrity_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	struct dm_mintegrity *v = ti->private;
	unsigned sz = 0;
	unsigned x;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%c", v->hash_failed ? 'C' : 'V');
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("%s %u %llu %llu %s ",
			v->dev->name,
			1 << v->dev_block_bits,
			(unsigned long long)v->data_blocks,
			(unsigned long long)v->hash_start,
			v->alg_name
			);
		for (x = 0; x < v->digest_size; x++) {
			DMEMIT("%02x", v->root_digest[x]);
		}
		DMEMIT(" ");
		if (!v->salt_size) {
			DMEMIT("-");
		} else {
			for (x = 0; x < v->salt_size; x++) {
				DMEMIT("%02x", v->salt[x]);
			}
		}
		break;
	}
}

static int mintegrity_ioctl(struct dm_target *ti, unsigned cmd,
			unsigned long arg)
{
	struct dm_mintegrity *v = ti->private;
	int r = 0;

	// TODO:
	// if (cmd == BLKFLSBUF)
	// 	mintegrity_sync(v);

	if (v->data_start_shift ||
	    ti->len != i_size_read(v->dev->bdev->bd_inode) >> SECTOR_SHIFT)
		r = scsi_verify_blk_ioctl(NULL, cmd);

	return r ? : __blkdev_driver_ioctl(v->dev->bdev, v->dev->mode,
				     cmd, arg);
}

static int mintegrity_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			struct bio_vec *biovec, int max_size)
{
	struct dm_mintegrity *v = ti->private;
	struct request_queue *q = bdev_get_queue(v->dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = v->dev->bdev;
	bvm->bi_sector = mintegrity_map_sector(v, bvm->bi_sector);

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int mintegrity_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct dm_mintegrity *v = ti->private;

	// TODO: iterate two disk combination?
	if (v->data_dev) {
		return fn(ti, v->data_dev, v->data_start_shift, ti->len, data);
	} else {
		return fn(ti, v->dev, v->data_start_shift, ti->len, data);
	}
}

static void mintegrity_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct dm_mintegrity *v = ti->private;

	// TODO: multi block?
	if (limits->logical_block_size < 1 << v->dev_block_bits)
		limits->logical_block_size = 1 << v->dev_block_bits;

	if (limits->physical_block_size < 1 << v->dev_block_bits)
		limits->physical_block_size = 1 << v->dev_block_bits;

	blk_limits_io_min(limits, limits->logical_block_size);
}

static void mintegrity_dtr(struct dm_target *ti)
{
	struct dm_mintegrity *v = ti->private;

	if (v->workqueue) {
		destroy_workqueue(v->workqueue);
	}

	if (v->created) {
		mintegrity_unmount_journal(v);
	}

	if (v->j_background_thread) {
		kthread_stop(v->j_background_thread);
	}

	delete_all_hash_blocks(v);

	if (v->data_page_mempool) {
		mempool_destroy(v->data_page_mempool);
	}

	if (v->data_block_mempool) {
		mempool_destroy(v->data_block_mempool);
	}

	if (v->journal_page_mempool) {
		mempool_destroy(v->journal_page_mempool);
	}

	if (v->journal_block_mempool) {
		mempool_destroy(v->journal_block_mempool);
	}

	kfree(v->hmac_digest);
	kfree(v->secret);
	kfree(v->salt);
	kfree(v->zero_digest);
	kfree(v->root_digest);
	kfree(v->hmac_desc);

	if (v->hmac_tfm) {
		crypto_free_shash(v->hmac_tfm);
	}

	if (v->tfm) {
		crypto_free_shash(v->tfm);
	}

	kfree(v->hmac_alg_name);
	kfree(v->alg_name);

	if (v->data_dev)
		dm_put_device(ti, v->data_dev);

	if (v->dev)
		dm_put_device(ti, v->dev);

	kfree(v);
}

/*
 * Target parameters:
 *	<data device>
 *	<block size>
 *  <number of hash blocks>
 *  <number of journal blocks>
 *  <number of data blocks>
 *  <data hash type>
 *  <root digest>
 *  <salt>
 *  <hmac hash type>
 *  <hmac secret>
 *  [<nozero>]
 *
 *	<salt>		Hex string or "-" if no salt.
 */
static int mintegrity_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	struct dm_mintegrity *v;
	unsigned num;
	unsigned long long num_ll;
	int r;
	int i;
	sector_t hash_position;
	char dummy;
	bool two_disks = (argc == 12);

	// Allocate struct dm_mintegrity for this device mapper instance
	v = kzalloc(sizeof(struct dm_mintegrity), GFP_KERNEL);
	if (!v) {
		ti->error = "Cannot allocate mintegrity structure";
		return -ENOMEM;
	}
	ti->private = v;
	v->ti = ti;
	v->two_disks = two_disks;

	// Check that dmsetup table is writeable
	// TODO: read only mode
	if (!(dm_table_get_mode(ti->table) & FMODE_WRITE)) {
		ti->error = "Device must be writeable!";
		r = -EINVAL;
		goto bad;
	}

	// Check argument count
	if (argc < 10) {
		ti->error = "Invalid argument count: 10 or more arguments required";
		r = -EINVAL;
		goto bad;
	}

	// argv[0] <data device>
	r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &v->dev);
	if (r) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	if (two_disks) {
		r = dm_get_device(ti, argv[1], dm_table_get_mode(ti->table), &v->data_dev);
		if (r) {
			ti->error = "Device lookup failed";
			goto bad;
		}
	} else {
	}

	// argv[1] <block size>
	if (sscanf(argv[1 + two_disks], "%u%c", &num, &dummy) != 1 ||
	    !num || (num & (num - 1)) ||
	    num < bdev_logical_block_size(v->dev->bdev) ||
	    num > PAGE_SIZE) {
		ti->error = "Invalid data device block size";
		r = -EINVAL;
		goto bad;
	}
	v->dev_block_bits = __ffs(num);
	v->dev_block_bytes = (1 << v->dev_block_bits);

	// argv[2] <number of hash blocks>
	if (sscanf(argv[2 + two_disks], "%llu%c", &num_ll, &dummy) != 1){
		ti->error = "Invalid number of hash blocks";
		r = -EINVAL;
		goto bad;
	}
	v->hash_blocks = num_ll;
	// 1, because skip superblock
	v->hash_start = 1;

	// argv[3] <number of journal blocks>
	if (sscanf(argv[3 + two_disks], "%llu%c", &num_ll, &dummy) != 1){
		ti->error = "Invalid number of journal blocks";
		r = -EINVAL;
		goto bad;
	}
	v->journal_blocks = num_ll;
	v->journal_start = v->hash_start + v->hash_blocks;

	// argv[4] <number of data blocks>
	if (sscanf(argv[4 + two_disks], "%llu%c", &num_ll, &dummy) != 1 ||
	    (sector_t)(num_ll << (v->dev_block_bits - SECTOR_SHIFT))
	    >> (v->dev_block_bits - SECTOR_SHIFT) != num_ll) {
		ti->error = "Invalid data blocks";
		r = -EINVAL;
		goto bad;
	}
	v->data_blocks = num_ll;
	v->data_start = two_disks ? 0 : v->journal_start + v->journal_blocks;

	// Check that device is long enough
	if (ti->len > (v->data_blocks << (v->dev_block_bits - SECTOR_SHIFT))) {
		ti->error = "Data device is too small";
		r = -EINVAL;
		goto bad;
	}

	// argv[5] <data hash type>
	v->alg_name = kstrdup(argv[5 + two_disks], GFP_KERNEL);
	if (!v->alg_name) {
		ti->error = "Cannot allocate algorithm name";
		r = -ENOMEM;
		goto bad;
	}

	// Allocate a crypto hash object based on algorithm name
	v->tfm = crypto_alloc_shash(v->alg_name, 0, 0);
	if (IS_ERR(v->tfm)) {
		ti->error = "Cannot initialize hash function";
		r = PTR_ERR(v->tfm);
		v->tfm = NULL;
		goto bad;
	}

	// Check that a disk block can hold at least 2 hashes
	v->digest_size = crypto_shash_digestsize(v->tfm);
	if ((1 << v->dev_block_bits) < v->digest_size * 2) {
		ti->error = "Digest size too big";
		r = -EINVAL;
		goto bad;
	}
	v->shash_descsize = sizeof(struct shash_desc) + crypto_shash_descsize(v->tfm);

	// Allocate space to keep track of root hash
	v->root_digest = kmalloc(v->digest_size, GFP_KERNEL);
	if (!v->root_digest) {
		ti->error = "Cannot allocate root digest";
		r = -ENOMEM;
		goto bad;
	}

	// argv[6] <root digest>
	if (strlen(argv[6 + two_disks]) != v->digest_size * 2 ||
	    hex2bin(v->root_digest, argv[6 + two_disks], v->digest_size)) {
		printk(KERN_CRIT "ROOT DIGEST: %s", argv[6 + two_disks]);
		ti->error = "Invalid root digest";
		r = -EINVAL;
		goto bad;
	}

	// argv[7] <salt>
	if (strcmp(argv[7 + two_disks], "-")) { // no salt if "-"
		v->salt_size = strlen(argv[7 + two_disks]) / 2;
		v->salt = kmalloc(v->salt_size, GFP_KERNEL);
		if (!v->salt) {
			ti->error = "Cannot allocate salt";
			r = -ENOMEM;
			goto bad;
		}
		if (strlen(argv[7 + two_disks]) != v->salt_size * 2 ||
		    hex2bin(v->salt, argv[7 + two_disks], v->salt_size)) {
			ti->error = "Invalid salt";
			r = -EINVAL;
			goto bad;
		}
	}

	// argv[8] <hmac hash type>
	v->hmac_alg_name = kstrdup(argv[8 + two_disks], GFP_KERNEL);
	if (!v->hmac_alg_name) {
		ti->error = "Cannot allocate algorithm name";
		r = -ENOMEM;
		goto bad;
	}

	// Allocate a crypto hash object based on algorithm name
	v->hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(v->hmac_tfm)) {
		ti->error = "Cannot initialize hash function";
		r = PTR_ERR(v->hmac_tfm);
		v->hmac_tfm = NULL;
		goto bad;
	}
	v->hmac_digest_size = crypto_shash_digestsize(v->hmac_tfm);
	v->hmac_desc = kzalloc(sizeof(struct shash_desc) +
		crypto_shash_descsize(v->hmac_tfm), GFP_KERNEL);
	if (!v->hmac_desc) {
		ti->error = "Cannot allocate mintegrity structure";
		return -ENOMEM;
	}
	v->hmac_digest = kzalloc(v->hmac_digest_size, GFP_KERNEL);
	if (!v->hmac_digest) {
		ti->error = "Cannot allocate mintegrity structure";
		return -ENOMEM;
	}

	v->hmac_desc->tfm = v->hmac_tfm;
	v->hmac_desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	// argv[9] <hmac secret>
	v->secret_size = strlen(argv[9 + two_disks]) / 2;
	v->secret = kmalloc(v->secret_size, GFP_KERNEL);
	if (!v->secret) {
		ti->error = "Cannot allocate secret";
		r = -ENOMEM;
		goto bad;
	}
	if (strlen(argv[9 + two_disks]) != v->secret_size * 2 ||
	    hex2bin(v->secret, argv[9 + two_disks], v->secret_size)) {
		ti->error = "Invalid secret";
		r = -EINVAL;
		goto bad;
	}

	// argv[10] [<nozero>]
	// Allocate space to keep track of a zero hash block
	if (!strcmp(argv[10 + two_disks], "lazy")) {
		struct shash_desc *desc;
		char c = 0;
		v->zero_digest = kmalloc(v->digest_size, GFP_KERNEL);
		if (!v->zero_digest) {
			ti->error = "Cannot allocate zero digest";
			r = -ENOMEM;
			goto bad;
		}
		// Pre-compute zero hash
		desc = kzalloc(sizeof(struct shash_desc) +
			crypto_shash_descsize(v->tfm), GFP_KERNEL);
		if (!desc) {
			ti->error = "Cannot allocate zero shash_desc";
			r = -ENOMEM;
			goto bad;
		}
		desc->tfm = v->tfm;
		desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
		r = crypto_shash_init(desc);
		if (r < 0) {
			kfree(desc);
			ti->error = "crypto_shash_init zero failed";
			r = -EINVAL;
			goto bad;
		}
		r = crypto_shash_update(desc, v->salt, v->salt_size);
		if (r < 0) {
			kfree(desc);
			ti->error = "crypto_shash_update zero failed";
			r = -EINVAL;
			goto bad;
		}
		for (i = 0; i < v->dev_block_bytes; i++) {
			r = crypto_shash_update(desc, &c, 1);
			if (r < 0) {
				kfree(desc);
				ti->error = "crypto_shash_update zero failed";
				r = -EINVAL;
				goto bad;
			}
		}
		r = crypto_shash_final(desc, v->zero_digest);
		if (r < 0) {
			kfree(desc);
			ti->error = "crypto_shash_final zero failed";
			r = -EINVAL;
			goto bad;
		}
	} else {
		ti->error = "Invalid optional argument";
		r = -EINVAL;
		goto bad;
	}

	// Compute start of each hash level
	v->hash_per_block_bits = __fls((1 << v->dev_block_bits) / v->digest_size);
	v->levels = 0;
	if (v->data_blocks)
		while (v->hash_per_block_bits * v->levels < 64 &&
		       (unsigned long long)(v->data_blocks - 1) >>
		       (v->hash_per_block_bits * v->levels))
			v->levels++;

	if (v->levels > DM_MINTEGRITY_MAX_LEVELS) {
		ti->error = "Too many tree levels";
		r = -E2BIG;
		goto bad;
	}

	hash_position = v->hash_start;
	for (i = v->levels - 1; i >= 0; i--) {
		sector_t s;
		v->hash_level_block[i] = hash_position;
		s = (v->data_blocks + ((sector_t)1 << ((i + 1) * v->hash_per_block_bits)) - 1)
					>> ((i + 1) * v->hash_per_block_bits);
		if (hash_position + s < hash_position) {
			ti->error = "Hash device offset overflow";
			r = -E2BIG;
			goto bad;
		}
		hash_position += s;
	}

	/* Initialize lock for IO operations */
	init_rwsem(&(v->j_lock));
	init_rwsem(&(v->data_tree_semaphore));
	init_rwsem(&(v->hash_tree_semaphore));
	INIT_LIST_HEAD(&v->clean_hash_list);
	INIT_LIST_HEAD(&v->dirty_hash_list);

	v->root_data_node = RB_ROOT;
	v->root_hash_node = RB_ROOT;

	// Read queue
	/* WQ_UNBOUND greatly improves performance when running on ramdisk */
	v->workqueue = alloc_workqueue("kmintegrityd_read",
		WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND, num_online_cpus() + 1);
	if (!v->workqueue) {
		ti->error = "Cannot allocate read workqueue";
		r = -ENOMEM;
		goto bad;
	}

	ti->per_bio_data_size = roundup(sizeof(struct dm_mintegrity_io) +
		v->shash_descsize + v->digest_size * 2 + (v->levels + 1) *
		sizeof(struct data_block*) + v->j_bpt * sizeof(struct journal_block),
		__alignof__(struct dm_mintegrity_io));

	r = mintegrity_recover_journal(v);
	if (r < 0) {
		ti->error = "Could not recover journal";
		r = -EIO;
		goto bad;
	}

	sema_init(&v->request_limit, 16384);
	v->created = 1;
	barrier();
	return 0;

bad:
	mintegrity_dtr(ti);
	return r;
}

// Struct for registering mintegrity
static struct target_type mintegrity_target = {
	.name		= "mintegrity",
	.version	= {1, 0, 0},
	.module		= THIS_MODULE,
	.ctr		= mintegrity_ctr,
	.dtr		= mintegrity_dtr,
	.map		= mintegrity_map,
	.status		= mintegrity_status,
	.ioctl		= mintegrity_ioctl,
	.merge		= mintegrity_merge,
	.iterate_devices = mintegrity_iterate_devices,
	.io_hints	= mintegrity_io_hints,
};

// Called on module loading
static int __init dm_mintegrity_init(void)
{
	int r;

	// Register mintegrity module
	r = dm_register_target(&mintegrity_target);
	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void __exit dm_mintegrity_exit(void)
{
	dm_unregister_target(&mintegrity_target);
}

module_init(dm_mintegrity_init);
module_exit(dm_mintegrity_exit);

MODULE_AUTHOR("Jan Kasiak <j.kasiak@gmail.com>");
MODULE_AUTHOR("Mikulas Patocka <mpatocka@redhat.com>");
MODULE_AUTHOR("Mandeep Baines <msb@chromium.org>");
MODULE_AUTHOR("Will Drewry <wad@chromium.org>");
MODULE_DESCRIPTION(DM_NAME " target for transparent RW disk integrity checking");
MODULE_LICENSE("GPL");
