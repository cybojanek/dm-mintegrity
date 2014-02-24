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

#include "dm-bufio.h"

#include <crypto/hash.h>
#include <linux/device-mapper.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define DM_MSG_PREFIX			"mintegrity"

#define DM_MINTEGRITY_IO_VEC_INLINE		16
#define DM_MINTEGRITY_MEMPOOL_SIZE		4
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

struct mint_journal_header {
	uint32_t magic;     /* 0x594c494c */
	uint32_t type;      /* Super/Descriptor/Commit Block */
	uint32_t sequence;  /* Sequence number */
	uint32_t options;   /* Options */
};

struct mint_journal_block_tag {
	uint32_t low;      /* Destination sector low */
	uint32_t high;     /* Destination sector high */
	uint32_t options;  /* Last or bits for escaped blocks */
};

struct mint_journal_superblock {
	struct mint_journal_header header;
	uint32_t blocks;      /* Number of block in this journal (including superblock) */
	uint32_t head;        /* Circular buffer head position */
	uint32_t tail;        /* Circular buffer tail position */
	uint32_t fill;        /* Number of used blocks */
	uint32_t sequence;    /* Current sequence number */
	char state;           /* Clean, Dirty */
};

/*
 * Auxiliary structure appended to each dm-bufio buffer. If the value
 * hash_verified is nonzero, hash of the block has been verified.
 *
 * The variable hash_verified is set to 0 when allocating the buffer, then
 * it can be changed to 1 and it is never reset to 0 again.
 *
 * There is no lock around this value, a race condition can at worst cause
 * that multiple processes verify the hash of the same buffer simultaneously
 * and write 1 to hash_verified simultaneously.
 * This condition is harmless, so we don't need locking.
 */
// TODO: this needs cleanup
struct buffer_aux {
	struct dm_buffer *self_buffer;  /* Pointer to own dm_buffer */
	struct buffer_aux *next_aux;    /* Next aux buffer for journal */
	struct dm_mintegrity *v;
	struct rw_semaphore lock;       /* RW semaphore lock for async write back */
	uint8_t hash_verified;          /* Buffer has been verified */
	uint8_t type;                   /* Buffer type */
};

struct dm_mintegrity {
	// Block device
	struct dm_dev *dev;
	struct dm_target *ti;
	struct dm_bufio_client *bufio;

	// Hash
	char *alg_name;        /* Hash algorithm name */
	char *hmac_alg_name;   /* HMAC hash algorithm name */

	uint32_t salt_size;    /* Size of salt */
	uint32_t secret_size;  /* Size of HMAC secret */

	uint8_t *root_digest;  /* Hash digest of the root block */
	uint8_t *salt;		   /* salt: its size is salt_size */
	uint8_t *secret;       /* HMAC secret: its size is secret_size */
	uint8_t *outer_pad;    /* Pre-computed outer pad */
	uint8_t *inner_pad;    /* Pre-computed inner pad */
	uint8_t *hmac_digest;  /* HMAC digest */

	struct crypto_shash *tfm;       /* Hash algorithm */
	struct crypto_shash *hmac_tfm;  /* HMAC hash algorithm */
	struct shash_desc *hmac_desc;   /* HMAC shash object */

	uint32_t digest_size;          /* hash digest size */
	uint32_t hmac_digest_size;	   /* HMAC hash digest size */

	uint32_t shash_descsize;       /* crypto temp space size */
	uint32_t hmac_shash_descsize;  /* crypto temp space size */

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
	mempool_t *vec_mempool;	/* mempool of bio vector */

	// Work queues
	struct workqueue_struct *read_wq;     /* workqueue for processing reads */
	struct workqueue_struct *write_wq;    /* workqeue for processing writes */
	struct workqueue_struct *journal_wq;  /* worqueue for journaling */

	// Locks
	struct rw_semaphore lock;    /* global read/write lock */
	struct rw_semaphore j_lock;  /* global journal read/write lock */
	struct rw_semaphore j_checkpoint_lock;  /* global journal sync lock */
	struct rw_semaphore j_commit_finish_lock;
	struct semaphore flush_semaphore;

	// Journal
	struct task_struct *j_background_thread;  /* Background journal thread */
	struct task_struct *j_flush_thread;  /* Background journal thread */
	struct mint_journal_superblock j_sb_header;  /* Current journal header */

	struct dm_buffer *j_sb_buffer;  /* Journal superblock buffer */
	struct dm_buffer *j_ds_buffer;  /* Journal descriptor buffer */

	atomic_t j_fill;     /* Number of blocks in journal - need atomic due to writeback */
	atomic_t j_checkpoint_remaining;  /* Number of blocks remaining to be written back */
	atomic_t j_commit_remaining;
	uint8_t committing;
	uint32_t j_blocks_to_free;  /* Number of blocks to free in journal after sync finishes */
	uint32_t j_ds_fill;  /* Number of tags in current descriptor buffer */
	uint32_t j_ds_max;   /* Max number of tags in descriptor buffer */
	uint32_t j_bpt;      /* Number of blocks required per transaction */
	uint32_t commit_count;

	struct buffer_aux *j_aux_buffer_head;  /* Head of modified blocks in journal */
	struct buffer_aux *j_aux_buffer_tail;  /* Tail of modified blocks in journal */

	/* starting blocks for each tree level. 0 is the lowest level. */
	sector_t hash_level_block[DM_MINTEGRITY_MAX_LEVELS];
};

struct dm_mintegrity_io {
	struct dm_mintegrity *v;  /* dm-mintegrity instance info */
	struct bio *bio;
	struct bio_vec *io_vec;
	sector_t block;     /* Start of block IO */

	uint32_t io_vec_size;
	uint32_t n_blocks;  /* Number of blocks in IO */

	/* A space for short vectors; longer vectors are allocated separately. */
	struct bio_vec io_vec_inline[DM_MINTEGRITY_IO_VEC_INLINE];

	struct work_struct work;  /* Work instance for read/write queue */

	bio_end_io_t *orig_bi_end_io;
	void *orig_bi_private;

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

struct dm_mintegrity_prefetch_work {
	struct work_struct work;
	struct dm_mintegrity *v;
	sector_t block;
	unsigned n_blocks;
};

static int mintegrity_checkpoint_journal(struct dm_mintegrity *v, int commit, int blocking);

static struct dm_buffer **io_dm_buffers(struct dm_mintegrity *v,
	struct dm_mintegrity_io *io)
{
	return (struct dm_buffer**)(io + 1);
}

static struct dm_buffer **io_dm_j_buffers(struct dm_mintegrity *v,
	struct dm_mintegrity_io *io)
{
	return (struct dm_buffer**)(io + 1) + v->levels + 1;
}

static struct shash_desc *io_hash_desc(struct dm_mintegrity *v,
	struct dm_mintegrity_io *io)
{
	return (struct shash_desc *)(
		(struct dm_buffer**)(io + 1) + v->levels + 1 + v->j_bpt);
}

static u8 *io_real_digest(struct dm_mintegrity *v, struct dm_mintegrity_io *io)
{
	return (u8*)((struct dm_buffer**)(io + 1) + v->levels + 1 + v->j_bpt) +
		v->shash_descsize;
}

static u8 *io_want_digest(struct dm_mintegrity *v, struct dm_mintegrity_io *io)
{
	return (u8*)((struct dm_buffer**)(io + 1) + v->levels + 1 + v->j_bpt) +
		v->shash_descsize + v->digest_size;
}

/*
 * Initialize struct buffer_aux for a freshly created buffer.
 */
static void dm_bufio_alloc_callback(struct dm_buffer *buf)
{
	struct buffer_aux *aux = dm_bufio_get_aux_data(buf);

	aux->self_buffer = NULL;
	aux->hash_verified = 0;
	aux->type = 0;
	init_rwsem(&(aux->lock));
}

/*
 * What do we want to do on a write callback ??
 */
 static void dm_bufio_endio_callback(struct dm_buffer *buf)
{
	struct buffer_aux *aux = dm_bufio_get_aux_data(buf);
	// if (aux->self_buffer)
	// 	printk(KERN_CRIT "got a type %i @ %lu!\n", aux->type, dm_bufio_get_block_number(aux->self_buffer));
	// TODO: move this to actual write finish callback
	// This was held by the journal - its been written back
	// so we can release it for modification
	if (aux->type == 1) {
		struct dm_mintegrity *v = aux->v;
		// We are no longer part of the list of dirty buffers
		// Do this before up_write, so that aux->type is 0 before
		// mintegrity_add_buffers_to_journal
		aux->type = 0;
		up_write(&(aux->lock));
		// Finished this checkpoint
		int r = atomic_dec_return(&v->j_checkpoint_remaining);
		if (r == 0) {
			// printk(KERN_CRIT "Flushing type 1!\n");
			// printk(KERN_CRIT "Incrementing semaphore!!\n");
			up(&v->flush_semaphore);
		} else if (r % 100 == 0) {
			// printk(KERN_CRIT "checkpoint: remaining: %i\n", r);
		}
	} else if (aux->type > 1) {
		struct dm_mintegrity *v = aux->v;
		int r = atomic_dec_return(&v->j_commit_remaining);
		if (r == 0 && v->committing) {
			// printk(KERN_CRIT "Finished type %i!\n", aux->type);
			// printk(KERN_CRIT "Finished flushing type 2!\n");
			up_write(&v->j_commit_finish_lock);
		}
	}
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
	if(r < 0){
		DMERR("crypto_shash_init failed: %d", r);
		return r;
	}

	r = crypto_shash_update(desc, v->salt, v->salt_size);
	if (r < 0) {
		DMERR("crypto_shash_update failed: %d", r);
		return r;
	}

	r = crypto_shash_update(desc, data, len);
	if (r < 0) {
		DMERR("crypto_shash_update failed: %d", r);
		return r;
	}

	r = crypto_shash_final(desc, io_real_digest(v, io));
	if (r < 0) {
		DMERR("crypto_shash_final failed: %d", r);
		return r;
	}

	return 0;
}

/*
 * Calculate hmac of root buffer. Clobbers v->hmac_desc and v->hmac_digest
 * Doesn't use locks, also assumes v->root_digest is locked.
 * Result hmac in v->hmac_digest
 * Based on RFC 2104
 *
 */
static int mintegrity_hmac_hash(struct dm_mintegrity *v)
{
	int r;

	r = crypto_shash_init(v->hmac_desc);
	if(r < 0){
		DMERR("crypto_shash_init failed: %d", r);
		return r;
	}

	r = crypto_shash_update(v->hmac_desc, v->inner_pad, v->hmac_digest_size);
	if (r < 0) {
		DMERR("crypto_shash_update failed: %d", r);
		return r;
	}

	r = crypto_shash_update(v->hmac_desc, v->root_digest, v->digest_size);
	if (r < 0) {
		DMERR("crypto_shash_update failed: %d", r);
		return r;
	}

	r = crypto_shash_final(v->hmac_desc, v->hmac_digest);
	if (r < 0) {
		DMERR("crypto_shash_final failed: %d", r);
		return r;
	}

	r = crypto_shash_init(v->hmac_desc);
	if(r < 0){
		DMERR("crypto_shash_init failed: %d", r);
		return r;
	}

	r = crypto_shash_update(v->hmac_desc, v->outer_pad, v->hmac_digest_size);
	if (r < 0) {
		DMERR("crypto_shash_update failed: %d", r);
		return r;
	}

	r = crypto_shash_update(v->hmac_desc, v->hmac_digest, v->hmac_digest_size);
	if (r < 0) {
		DMERR("crypto_shash_update failed: %d", r);
		return r;
	}

	r = crypto_shash_final(v->hmac_desc, v->hmac_digest);
	if (r < 0) {
		DMERR("crypto_shash_final failed: %d", r);
		return r;
	}

	return 0;
}

static int mintegrity_commit_journal(struct dm_mintegrity *v)
{
	int ret = 0;
	sector_t sector;
	u8 *data;
	struct buffer_aux *aux;
	struct mint_journal_superblock *js = &v->j_sb_header;
	struct dm_buffer *j_cm_buffer;
	struct mint_journal_header mjh_commit = {cpu_to_le32(MJ_MAGIC),
		cpu_to_le32(TYPE_MJCB), cpu_to_le32(v->j_sb_header.sequence), 0};
	struct mint_journal_header mjh_descriptor = {cpu_to_le32(MJ_MAGIC),
		cpu_to_le32(TYPE_MJDB), cpu_to_le32(v->j_sb_header.sequence + 1), 0};

	// Nothing to commit
	if (v->j_ds_fill == 0) {
		return ret;
	}

	// Increment sequence counter
	v->j_sb_header.sequence++;

	// descriptor block
	down_write(&v->j_commit_finish_lock);
	v->committing = 1;
	atomic_inc(&v->j_commit_remaining);
	aux = dm_bufio_get_aux_data(v->j_ds_buffer);
	aux->v = v;
	aux->type = 3;
	aux->self_buffer = v->j_ds_buffer;
	dm_bufio_mark_buffer_dirty(v->j_ds_buffer);
	dm_bufio_release(v->j_ds_buffer);
	// Change this to ASYNC
	dm_bufio_write_dirty_buffers_async(v->bufio);
	// sync journal buffers
	// already marked dirty

	// Calculate hmac
	mintegrity_hmac_hash(v);

	// This means we're screwed and don't have room for a commit block
	BUG_ON(atomic_read(&v->j_fill) == v->journal_blocks - 1);

	// Get commit block - always available
	sector = v->journal_start + 1 + ((js->tail) % (v->journal_blocks - 1));
	BUG_ON(sector >= v->data_start);
	BUG_ON(sector < v->journal_start);
	data = dm_bufio_new(v->bufio, sector, &j_cm_buffer);
	// TODO: how do we recover from this?
	if (unlikely(IS_ERR(data))) {
		BUG_ON(1);
		return PTR_ERR(data);
	}

	// Increment tail position
	js->tail = (js->tail + 1) % (v->journal_blocks - 1);
	// Increment fill
	atomic_inc(&v->j_fill);

	// Copy over commit header and following hmac
	memcpy(data, &mjh_commit, sizeof(struct mint_journal_header));
	memcpy(data + sizeof(struct mint_journal_header), v->hmac_digest,
		v->hmac_digest_size);
	// Make sure descriptor block and journal buffers synced - wait for lock instead
	// printk(KERN_CRIT "Waiting for commit finish lock!\n");
	down_write(&v->j_commit_finish_lock);
	// printk(KERN_CRIT "Stopped Waiting for commit finish lock!\n");
	dm_bufio_issue_flush(v->bufio);
	// printk(KERN_CRIT "Finished waiting for  flush!\n");
	// dm_bufio_write_dirty_buffers(v->bufio);
	// sync commit block	
	v->committing = 1;
	atomic_inc(&v->j_commit_remaining);
	aux = dm_bufio_get_aux_data(j_cm_buffer);
	aux->v = v;
	aux->type = 4;
	aux->self_buffer = j_cm_buffer;
	dm_bufio_mark_buffer_dirty(j_cm_buffer);
	dm_bufio_release(j_cm_buffer);
	dm_bufio_write_dirty_buffers_async(v->bufio);
	// printk(KERN_CRIT "Waiting 2 for commit finish lock!\n");
	down_write(&v->j_commit_finish_lock);
	dm_bufio_issue_flush(v->bufio);
	// printk(KERN_CRIT "Stopped 2 Waiting for commit finish lock!\n");
	up_write(&v->j_commit_finish_lock);
	v->committing = 0;

	v->j_ds_fill = 0;
	if (atomic_read(&v->j_fill) == v->journal_blocks - 1) {
		// No room for a new descriptor block - sync journal, blocking
		mintegrity_checkpoint_journal(v, 1, 1);
		ret = 1;
	}

	// Get new desciptor block
	sector = v->journal_start + 1 + ((js->tail) % (v->journal_blocks - 1));
	data = dm_bufio_new(v->bufio, sector, &v->j_ds_buffer);
	if (unlikely(IS_ERR(data))) {
		BUG_ON(1 == 1);
		return PTR_ERR(data);
	}

	// Increment tail position
	js->tail = (js->tail + 1) % (v->journal_blocks - 1);
	// Increment fill
	atomic_inc(&v->j_fill);

	// Copy descriptor header
	memcpy(data, &mjh_descriptor, sizeof(struct mint_journal_header));
	return ret;
}

static void mintegrity_add_buffers_to_journal(struct dm_mintegrity *v,
	sector_t sector, struct dm_buffer **data_buffers,
	struct dm_buffer **journal_buffers, int error, char *tag_ptr)
{
	int i;
	struct mint_journal_block_tag tag = {cpu_to_le32(sector),
		cpu_to_le32(sector >> 32), 0};

	if (likely(data_buffers != NULL)) {
		// Lock because we'll be modifying buffer list
		down_write(&v->j_lock);

		// Add modified blocks to writeback list
		for (i = 0; i < v->levels + 1; i++) {
			// Skip NULL buffer pointers
			if (!data_buffers[i]) {
				continue;
			}
			struct buffer_aux *aux = dm_bufio_get_aux_data(data_buffers[i]);
			if (aux->type == 1) {  // Already held by journal
				dm_bufio_release(data_buffers[i]);
			} else {
				aux->type = 1;
				aux->self_buffer = data_buffers[i];
				aux->next_aux = NULL;
				aux->v = v;

				if (v->j_aux_buffer_head == NULL) {
					v->j_aux_buffer_head = aux;
					v->j_aux_buffer_tail = aux;
				} else {
					v->j_aux_buffer_tail->next_aux = aux;
					v->j_aux_buffer_tail = aux;
				}
			}
		}

		// Unlock
		up_write(&v->j_lock);
	}

	// Add journal blocks
	for (i = 0; i < v->j_bpt; i++) {
		struct buffer_aux *aux = dm_bufio_get_aux_data(journal_buffers[i]);
		aux->type = 2;
		aux->v = v;
		aux->self_buffer = journal_buffers[i];
		atomic_inc(&v->j_commit_remaining);
		// Check if magic numbers match
		if (memcmp(dm_bufio_get_block_data(journal_buffers[i]),
			dm_bufio_get_block_data(v->j_ds_buffer), 4)) {
			// Escape magic number
			memset(dm_bufio_get_block_data(journal_buffers[i]), 4, 0);
			// Mark escaped
			tag.options = tag.options | (2 << i);
		}
		// printk(KERN_CRIT "Marking buffer: %lu as type 2\n", dm_bufio_get_block_number(journal_buffers[i]));
		dm_bufio_mark_buffer_dirty(journal_buffers[i]);
		dm_bufio_release(journal_buffers[i]);
	}

	// Tell journal to ignore
	if (unlikely(error)) {
		tag.options = tag.options | 1;
	}
	// memcpy(tag_ptr, &tag, sizeof(struct mint_journal_block_tag));
}

static int mintegrity_checkpoint_journal(struct dm_mintegrity *v, int commit, int blocking)
{
	// struct mint_journal_superblock *js = &v->j_sb_header;
	struct buffer_aux *b;
	int i = 0;

	if (blocking == 1) {
		printk(KERN_CRIT "Blocking journal checkpoint!\n");
	}
	// printk(KERN_CRIT "Journal: %s, %s\n", commit ? "check" : "not check",
	// 	blocking ? "sync" : "async");

	// commit anything so far - if commit did not call us
	if (!commit && mintegrity_commit_journal(v) == 1) {
		// sync was called from commit - we're done
		return 0;
	}

	// Wait until ongoing sync finishes
	// printk(KERN_CRIT "Getting checkpoint lock...\n");
	if (blocking == 3) {
		if (!down_write_trylock(&v->j_checkpoint_lock)) { return 0;}
	} else {
		down_write(&v->j_checkpoint_lock);
	}
	// printk(KERN_CRIT "Got checkpoint lock...\n");

	// Count the number of buffers that will be written back
	b = v->j_aux_buffer_head;
	while (b) {
		i++;
		b = b->next_aux;
	}
	// Nothing to sync
	if (i == 0) {
		up_write(&v->j_checkpoint_lock);
		return 0;
	}


	atomic_set(&v->j_checkpoint_remaining, i);
	v->j_blocks_to_free = atomic_read(&v->j_fill) + (commit ? 0 : -1);
	// printk(KERN_CRIT "Sync: %i blocks, free: %i\n", i, v->j_blocks_to_free);

	// Mark dirty and release all data that was commited
	while (v->j_aux_buffer_head) {
		// Temp pointer
		struct buffer_aux *b = v->j_aux_buffer_head;
		// Increment head
		v->j_aux_buffer_head = v->j_aux_buffer_head->next_aux;
		// Lock down buffer until it's written back
		down_write(&b->lock);
		dm_bufio_mark_buffer_dirty(b->self_buffer);
		dm_bufio_release(b->self_buffer);
	}

	// Now write everything back - blocking
	if (blocking == 1) {
		dm_bufio_write_dirty_buffers(v->bufio);
	} else {
		dm_bufio_write_dirty_buffers_async(v->bufio);
	}
	return 0;
}

static int mintegrity_get_journal_buffers(struct dm_mintegrity *v,
	struct dm_buffer **buffers, uint8_t **tag)
{
	int i, j;
	u8 *data;
	sector_t sector;
	struct mint_journal_superblock *js = &v->j_sb_header;

	// Lock journal
	down_write(&v->j_lock);

	// Check if we have space in the descriptor block for a tag
	if (v->j_ds_fill == v->j_ds_max) {
		// We don't lets get a new one
		mintegrity_commit_journal(v);
		if (v->commit_count++ % 5 == 0)
			mintegrity_checkpoint_journal(v, 0, 3);
	}

	// Check for space - need blocks per transaction + commit block
	if (atomic_read(&v->j_fill) + 1 + v->j_bpt > v->journal_blocks - 1) {
		// Make space in journal - blocking
		mintegrity_checkpoint_journal(v, 0, 1);
	}

	// Get blocks for this transaction
	for (i = 0; i < v->j_bpt; i++) {
		sector = v->journal_start + 1 + ((js->tail + i) % (v->journal_blocks - 1));
		data = dm_bufio_new(v->bufio, sector, buffers + i);
		if (unlikely(IS_ERR(data))) {
			// Error getting buffer - release all the ones we got
			for (j = 0; j < i; j++) {
				dm_bufio_release(buffers[j]);
			}
			up_write(&v->j_lock);
			return PTR_ERR(data);
		}
	}

	// Increment tail position
	js->tail = (js->tail + v->j_bpt) % (v->journal_blocks - 1);
	// Increment fill
	atomic_add(v->j_bpt, &v->j_fill);

	// struct mint_journal_block_tag location in descriptor block
	*tag = dm_bufio_get_block_data(v->j_ds_buffer) + 
		sizeof(struct mint_journal_header) + v->j_ds_fill *
		sizeof(struct mint_journal_block_tag);
	// Increment descriptor block fill
	v->j_ds_fill++;

	// if (v->j_ds_fill % 100 == 0) {
	// 	dm_bufio_write_dirty_buffers_async(v->bufio);
	// }

	// Unlock journal
	up_write(&v->j_lock);

	return 0;
}

static int mintegrity_recover_journal(struct dm_mintegrity *v)
{
	u8 *data;
	sector_t sector;
	struct mint_journal_superblock *js = &v->j_sb_header;
	struct mint_journal_header mjh_descriptor = {cpu_to_le32(MJ_MAGIC),
		cpu_to_le32(TYPE_MJDB), 0, 0};


	// Journal setup
	data = dm_bufio_read(v->bufio, v->journal_start, &v->j_sb_buffer);
	if (IS_ERR(data)) {
		return -EIO;
	}

	// Read journal superblock and convert to local endianness
	memcpy(&v->j_sb_header, dm_bufio_get_block_data(v->j_sb_buffer),
		sizeof(struct mint_journal_superblock));
	v->j_sb_header.blocks = le32_to_cpu(v->j_sb_header.blocks);
	v->j_sb_header.head = le32_to_cpu(v->j_sb_header.head);
	v->j_sb_header.tail = le32_to_cpu(v->j_sb_header.tail);
	v->j_sb_header.fill = le32_to_cpu(v->j_sb_header.fill);
	v->j_sb_header.sequence = le32_to_cpu(v->j_sb_header.sequence);
	v->j_sb_header.sequence = 0;

	// data = dm_bufio_new(v->bufio, v->journal_start + 1, &v->j_ds_buffer);
	// if (IS_ERR(data)) {
	// 	return -EINVAL;
	// }

	// // Set up first journal descriptor block
	// struct mint_journal_header mjh = {
	// 	cpu_to_le32(MJ_MAGIC), cpu_to_le32(TYPE_MJDB), 0, 0};
	// memcpy(v->journal_descriptor_block.data, &mjh, sizeof(struct mint_journal_header));
	// v->journal_descriptor_fill = 0;
	// v->journal_descriptor_capacity = (v->journal_superblock.block_size - 
	// 	sizeof(struct mint_journal_header)) / sizeof(struct mint_journal_block_tag);

	// Max number of block tags in one journal descriptor block
	v->j_ds_max = (v->dev_block_bytes - sizeof(struct mint_journal_header)) /
		sizeof(struct mint_journal_block_tag);
	printk(KERN_CRIT "j_ds_max: %i\n", v->j_ds_max);
	// Number of blocks necessary per transaction - packed digests + data block
	v->j_bpt = DIV_ROUND_UP(v->levels, (v->dev_block_bytes / v->digest_size)) + 1;
	v->j_ds_fill = 0;

	// Need at least one transaction + superblock + descriptor + commit
	if (v->journal_blocks < v->j_bpt + 3) {
		return -EINVAL;
	}

	// Read new descriptor block
	sector = v->journal_start + 1;
	data = dm_bufio_new(v->bufio, sector, &v->j_ds_buffer);
	if (unlikely(IS_ERR(data))) {
		return PTR_ERR(data);
	}

	js->tail = 1;
	// js->fill = 1;
	atomic_set(&v->j_fill, 1);

	// Copy descriptor header
	memcpy(data, &mjh_descriptor, sizeof(struct mint_journal_header));

	atomic_set(&v->j_commit_remaining, 0);
	v->committing = 0;

	return 0;
	/**
	struct mint_block j_data_block;
	struct mint_block j_hash_block;
	struct mint_block block;
	sector_t data_sector, hash_sector;
	unsigned offset;
	u8 *result;
	int i;
	int j;
	int r;
	struct mint_journal_superblock *mjsb = &v->journal_superblock;
	// Check magic number
	const char mjsb_magic[16] = {0x6c, 0x69, 0x6c, 0x79, 0x6d, 0x75, 0x66,
		0x66, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	if (memcmp(mjsb->magic, mjsb_magic, 16)) {
		DMERR("Journal superblock magic number does not match");
		return -EIO;
	}

	// Clean!
	if (mjsb->state == 0)
		return 0;

	struct dm_mintegrity_io *io = (struct dm_mintegrity_io*)
		kzalloc(v->ti->per_bio_data_size, GFP_KERNEL);

	if (!io)
		return -ENOMEM;

	for (i = 0; i < mjsb->fill; i++) {
		int b = (mjsb->head + i) % mjsb->capacity;
		j_data_block.data = NULL;
		j_hash_block.data = NULL;
		block.data = NULL;

		// Read hash block
		j_hash_block.data = dm_bufio_read(v->bufio, v->journal_start + (b + 1) * 2,
			&j_hash_block.buf);
		if (IS_ERR(j_hash_block.data)) {
			DMERR("Failed to read journal hash block: %d", b);
			goto bad;
		}
		// Set up root
		memcpy(v->root_digest, j_hash_block.data + v->levels * v->digest_size +
			sizeof(sector_t), v->digest_size);

		// Compute hmac
		r = mintegrity_hmac_hash(io);
		if (r < 0) {
			DMERR("Failed to calculate hmac for journal block: %d", b);
			goto bad;
		}

		// Verify match
		result = io_hmac_digest(v, io);
		if(memcmp(j_hash_block.data + v->levels * v->digest_size + sizeof(sector_t)
			+ v->digest_size, result, v->hmac_digest_size)) {
			DMERR("Journal hmac does not verify for block: %d", b);
			goto bad;
		}

		// Get logical data sector
		memcpy(&data_sector, j_hash_block.data + v->levels * v->digest_size,
			sizeof(sector_t));
		if (data_sector > v->data_blocks) {
			DMERR("Journdal data block IO out of range: %llu > %llu",
				(unsigned long long)data_sector,
				(unsigned long long)v->data_blocks);
			goto bad;
		}

		// Write out hashes
		for (j = 0; i < v->levels; j++) {
			// Get hash positions
			mintegrity_hash_at_level(v, data_sector, j, &hash_sector, &offset);
			// Read current hash block from disk
			block.data = dm_bufio_read(v->bufio, hash_sector, &block.buf);
			if (IS_ERR(block.data)) {
				DMERR("Failed to get hash");
				goto bad;
			}
			// Copy in changes
			memcpy(block.data + offset, j_hash_block.data + j * v->digest_size,
				v->digest_size);
			// Write back to disk
			dm_bufio_mark_buffer_dirty(block.buf);
			dm_bufio_release(block.buf);
			block.data = NULL;
		}
		dm_bufio_release(j_hash_block.buf);
		j_hash_block.data = NULL;

		// Read data block
		j_data_block.data = dm_bufio_read(v->bufio, v->journal_start + 1 + b * 2,
			&j_data_block.buf);
		if (IS_ERR(j_data_block.data)) {
			DMERR("Failed to read journal data block: %d", b);
			goto bad;
		}

		// Get new data block
		block.data = dm_bufio_new(v->bufio, v->data_start + data_sector, &block.buf);
		if (IS_ERR(block.data)) {
			DMERR("Failed to get new data block for recovery");
			goto bad;
		}

		// Write it out
		memcpy(block.data, j_data_block.data, v->dev_block_bytes);
		dm_bufio_mark_buffer_dirty(block.buf);
		dm_bufio_release(block.buf);
		dm_bufio_release(j_data_block.buf);
	}

	// Sync everything
	dm_bufio_write_dirty_buffers(v->bufio);

	// Write out journal superblock - clean
	mjsb->state = 0;
	mjsb->fill = 0;
	mjsb->head = 0;
	mjsb->tail = 0;
	memcpy(v->journal_superblock.data, mjsb,
		sizeof(struct mint_journal_superblock));
	dm_bufio_mark_buffer_dirty(v->journal_superblock.buf);
	dm_bufio_write_dirty_buffers(v->bufio);

	kfree(io);
	return 0;

bad:
	if (j_data_block.data)
		dm_bufio_release(j_data_block.buf);

	if (j_hash_block.data)
		dm_bufio_release(j_hash_block.buf);

	if (block.data)
		dm_bufio_release(block.buf);

	kfree(io);
	return -EIO;
	*/
}

static int mintegrity_background_journal_thread(void *arg)
{
	struct dm_mintegrity *v = (struct dm_mintegrity*)arg;
	// Loop forever
	while (1) {
		// dm-mintegrity called kthread_stop
		if (kthread_should_stop()) {
			break;
		}
		// Get write lock - we need this
		down_write(&v->lock);
		// Call async!
		mintegrity_checkpoint_journal(v, 0, 0);
		// Done with write lock
		up_write(&v->lock);
		// Sleep 5 seconds
		msleep(5000);
	}
	return 0;
}

static int mintegrity_background_flush_thread(void *arg)
{
	struct dm_mintegrity *v = (struct dm_mintegrity*)arg;
	// Loop forever
	while (1) {
		// dm-mintegrity called kthread_stop
		if (kthread_should_stop()) {
			break;
		}
		if (v->committing != 3 && down_interruptible(&v->flush_semaphore)) {
			// signal
		} else {
			if(v->committing == 3) {
				continue;
			}
			// printk(KERN_CRIT "Issuing flush!\n");
			dm_bufio_issue_flush(v->bufio);
				struct mint_journal_superblock *js = &v->j_sb_header;
			js->head = (js->head + v->j_blocks_to_free) %
				(v->journal_blocks - 1);
			atomic_sub(v->j_blocks_to_free, &v->j_fill);
			up_write(&v->j_checkpoint_lock);
		}
		// // Get write lock - we need this
		// down_write(&v->lock);
		// // Call async!
		// mintegrity_checkpoint_journal(v, 0, 0);
		// // Done with write lock
		// up_write(&v->lock);
		// // Sleep 5 seconds
		// msleep(5000);
	}
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
	int level, bool skip_unverified, struct dm_buffer **dmb)
{
	struct dm_mintegrity *v = io->v;
	struct dm_buffer *buf;
	struct buffer_aux *aux;
	u8 *data;
	int r;
	sector_t hash_block;
	unsigned offset;

	mintegrity_hash_at_level(v, block, level, &hash_block, &offset);

	data = dm_bufio_read(v->bufio, hash_block, &buf);
	if (unlikely(IS_ERR(data)))
		return PTR_ERR(data);

	aux = dm_bufio_get_aux_data(buf);

	if (!aux->hash_verified) {
		u8 *result;

		if (skip_unverified) {
			r = 1;
			goto release_ret_r;
		}

		r = mintegrity_buffer_hash(io, data, v->dev_block_bytes);
		if (r != 0) {
			goto release_ret_r;
		}

		result = io_real_digest(v, io);

		if (unlikely(memcmp(result, io_want_digest(v, io), v->digest_size))) {
			DMERR_LIMIT("metadata block %llu is corrupted",
				(unsigned long long)hash_block);
			v->hash_failed = 1;
			r = -EIO;
			goto release_ret_r;
		} else {
			aux->hash_verified = 1;
		}
	}

	memcpy(io_want_digest(v, io), data + offset, v->digest_size);

	// Return back the whole block we read and verified
	if (dmb) {
		*dmb = buf;
	} else {
		dm_bufio_release(buf);
	}

	return 0;

	release_ret_r:
	dm_bufio_release(buf);

	return r;
}

/*
 * Verify one "dm_mintegrity_io" structure.
 */
static int mintegrity_verify_read_io(struct dm_mintegrity_io *io)
{
	struct dm_mintegrity *v = io->v;
	unsigned b;
	int i;
	unsigned vector = 0, offset = 0;

	for (b = 0; b < io->n_blocks; b++) {
		u8 *result;
		int r;
		unsigned todo;
		sector_t data_sector;
		u8 *data;
		struct dm_buffer *dm_buffer;
		data_sector = io->block + b;

		if (likely(v->levels)) {
			/*
			 * First, we try to get the requested hash for
			 * the current block. If the hash block itself is
			 * verified, zero is returned. If it isn't, this
			 * function returns 0 and we fall back to whole
			 * chain verification.
			 */
			int r = mintegrity_verify_level(io, data_sector, 0, true, NULL);
			if (likely(!r))
				goto test_block_hash;
			if (r < 0)
				return r;
		}

		memcpy(io_want_digest(v, io), v->root_digest, v->digest_size);

		for (i = v->levels - 1; i >= 0; i--) {
			int r = mintegrity_verify_level(io, data_sector, i, false, NULL);
			if (unlikely(r))
				return r;
		}


	test_block_hash:
		// Read data block
		data = dm_bufio_get(v->bufio, data_sector + v->data_start, &dm_buffer);

		if (data) {
			printk(KERN_CRIT "Reading from bufio get!\n");
			r = mintegrity_buffer_hash(io, data, v->dev_block_bytes);
			if (r != 0) {
				dm_bufio_release(dm_buffer);
				return -EIO;
			}

			result = io_real_digest(v, io);

			if (unlikely(memcmp(result, io_want_digest(v, io), v->digest_size))) {
				DMERR_LIMIT("data block %llu is corrupted",
					(unsigned long long)(io->block + b));
				v->hash_failed = 1;
				dm_bufio_release(dm_buffer);
				return -EIO;
			}

			todo = 1 << v->dev_block_bits;
			do {
				struct bio_vec *bv;
				u8 *page;
				unsigned len;

				BUG_ON(vector >= io->io_vec_size);
				bv = &io->io_vec[vector];
				page = kmap_atomic(bv->bv_page);
				len = bv->bv_len - offset;
				if (likely(len >= todo))
					len = todo;

				memcpy(page + bv->bv_offset + offset,
					data + v->dev_block_bytes - todo, len);
				kunmap_atomic(page);

				offset += len;
				if (likely(offset == bv->bv_len)) {
					offset = 0;
					vector++;
				}
				todo -= len;
			} while (todo);

			dm_bufio_release(dm_buffer);
		} else {
			struct shash_desc *desc;
			desc = io_hash_desc(v, io);
			desc->tfm = v->tfm;
			desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
			r = crypto_shash_init(desc);
			if (r < 0) {
				DMERR("crypto_shash_init failed: %d", r);
				return r;
			}
			r = crypto_shash_update(desc, v->salt, v->salt_size);
			if (r < 0) {
				DMERR("crypto_shash_update failed: %d", r);
				return r;
			}
			todo = 1 << v->dev_block_bits;
			do {
				struct bio_vec *bv;
				u8 *page;
				unsigned len;

				BUG_ON(vector >= io->io_vec_size);
				bv = &io->io_vec[vector];
				page = kmap_atomic(bv->bv_page);
				len = bv->bv_len - offset;
				if (likely(len >= todo))
					len = todo;
				r = crypto_shash_update(desc,
						page + bv->bv_offset + offset, len);
				kunmap_atomic(page);
				if (r < 0) {
					DMERR("crypto_shash_update failed: %d", r);
					return r;
				}
				offset += len;
				if (likely(offset == bv->bv_len)) {
					offset = 0;
					vector++;
				}
				todo -= len;
			} while (todo);

			result = io_real_digest(v, io);
			r = crypto_shash_final(desc, result);
			if (r < 0) {
				DMERR("crypto_shash_final failed: %d", r);
				return r;
			}
			if (unlikely(memcmp(result, io_want_digest(v, io), v->digest_size))) {
				DMERR_LIMIT("data block %llu is corrupted",
					(unsigned long long)(io->block + b));
				v->hash_failed = 1;
				return -EIO;
			}
		}
	}
	BUG_ON(vector != io->io_vec_size);
	BUG_ON(offset);

	return 0;
}

static int mintegrity_verify_write_io(struct dm_mintegrity_io *io)
{
	unsigned b;
	int i, j;
	unsigned vector = 0;
	unsigned offset = 0;
	struct dm_mintegrity *v = io->v;

	for (b = 0; b < io->n_blocks; b++) {
		int r;
		u8 *result;
		u8 *data;
		unsigned todo;
		uint8_t *tag = NULL;

		// Pointers for modified hash and data block
		struct dm_buffer **dm_buffers = io_dm_buffers(v, io);
		// Pointers for jounral entries
		struct dm_buffer **dm_j_buffers = io_dm_j_buffers(v, io);
		sector_t sector = io->block + b;

		// Get journal blocks
		if ((r = mintegrity_get_journal_buffers(v, dm_j_buffers, &tag)) != 0) {
			DMERR("get journal buffers failed: %d", r);
			// Safe to return because nothing needs to be cleaned up here
			return -EIO;
		}

		// The io digest we want is the root
		memcpy(io_want_digest(v, io), v->root_digest, v->digest_size);

		// Set all to NULL for possible cleanup
		for (i = 0; i < v->levels + 1; i++) {
			dm_buffers[i] = NULL;
		}

		// Read levels, TOP DOWN and compare to io want, which is set after
		// every successive read
		int dd = 0;
		for (i = v->levels - 1; i >= 0; i--) {
			r = mintegrity_verify_level(io, sector, i, false, dm_buffers + i);
			dd++;
			BUG_ON(dm_buffers[i] == NULL);
			if (unlikely(r != 0)) {
				for (j = v->levels - 1; j > i; j--) {
					dm_bufio_release(dm_buffers[j]);
				}
				mintegrity_add_buffers_to_journal(v, sector, NULL, dm_j_buffers,
					-EIO, tag);
				return -EIO;
			}
			BUG_ON(dm_buffers[i] == NULL);
		}
		BUG_ON(dd != v->levels);
		BUG_ON(dm_buffers[1] == NULL);
		BUG_ON(dm_buffers[0] == NULL);
		BUG_ON(dm_j_buffers[0] == NULL);
		// Copy from bio vector to journal data dm_buffer
		todo = v->dev_block_bytes;
		do {
			struct bio_vec *bv;
			u8 *page;
			unsigned len;

			BUG_ON(vector >= io->io_vec_size);
			bv = &io->io_vec[vector];
			page = kmap_atomic(bv->bv_page);
			len = bv->bv_len - offset;
			if (likely(len >= todo)){
				len = todo;
			}
			memcpy(dm_bufio_get_block_data(dm_j_buffers[0])
				+ v->dev_block_bytes - todo,
				page + bv->bv_offset + offset, len);
			kunmap_atomic(page);
			offset += len;
			if (likely(offset == bv->bv_len)) {
				offset = 0;
				vector++;
			}
			todo -= len;
		} while (todo);
		BUG_ON(dm_buffers[0] == NULL);

		// Compute new data hash
		r = mintegrity_buffer_hash(io, dm_bufio_get_block_data(dm_j_buffers[0]),
			v->dev_block_bytes);
		if (r != 0) {
			goto bad;
		}
		BUG_ON(dm_buffers[0] == NULL);

		result = io_real_digest(v, io);
		BUG_ON(dm_buffers[0] == NULL);

		// Acquire and release locks for everything in hash levels
		// journal sync finished
		for (i = 0; i < v->levels; i++) {
			struct buffer_aux *b = dm_bufio_get_aux_data(dm_buffers[i]);
			down_write(&b->lock);
			up_write(&b->lock);
		}

		BUG_ON(dm_buffers[0] == NULL);
		// Copy data hash into first level
		memcpy(dm_bufio_get_block_data(dm_buffers[0]) +
			mintegrity_hash_buffer_offset(v, sector, 0), result, v->digest_size);
		// Copy into journal buffer
		BUG_ON(dm_j_buffers[1] == NULL);
		memcpy(dm_bufio_get_block_data(dm_j_buffers[1]), result, v->digest_size);

		// Write things back bottom up
		for (i = 1; i < v->levels; i++) {
			// Calculate hash for level below
			BUG_ON(dm_buffers[i - 1] == NULL);
			r = mintegrity_buffer_hash(io,
				dm_bufio_get_block_data(dm_buffers[i - 1]), v->dev_block_bytes);
			if (r < 0) {
				DMERR("failed to calculate write buffer hash for level");
				goto bad;
			}
			result = io_real_digest(v, io);
			// Copy hash into current level
			BUG_ON(dm_buffers[i] == NULL);
			memcpy(dm_bufio_get_block_data(dm_buffers[i]) +
				mintegrity_hash_buffer_offset(v, sector, i), result,
				v->digest_size);
			// Copy into journal buffer
			// TODO: check that is correct
			// memcpy(dm_bufio_get_block_data(dm_j_buffers[DIV_ROUND_UP(
			// 	i * v->digest_size, v->dev_block_bytes) + 1]) +
			// 	((i * v->digest_size) % v->dev_block_bytes), result,
			// 	v->digest_size);
		}
		// Update root merkle tree hashes
		BUG_ON(dm_buffers[v->levels - 1] == NULL);
		r = mintegrity_buffer_hash(io,
			dm_bufio_get_block_data(dm_buffers[v->levels - 1]),
			v->dev_block_bytes);
		if (r < 0) {
			DMERR("failed to calculate write buffer hash for level");
			goto bad;
		}
		result = io_real_digest(v, io);
		memcpy(v->root_digest, result, v->digest_size);
		// Copy into journal buffer
		// TODO: check that is correct
		// memcpy(dm_bufio_get_block_data(dm_j_buffers[DIV_ROUND_UP(
		// 		(v->levels - 1) * v->digest_size, v->dev_block_bytes) + 1]) +
		// 		(((v->levels - 1) * v->digest_size) % v->dev_block_bytes),
		// 		result, v->digest_size);

		// Get ready to write to disk
		data = dm_bufio_new(v->bufio, sector + v->data_start,
			dm_buffers + v->levels);
		if (unlikely(IS_ERR(data))){
			dm_buffers[v->levels] = NULL;
			goto bad;
		}

		BUG_ON(dm_buffers[v->levels] == NULL);
		memcpy(dm_bufio_get_block_data(dm_buffers[v->levels]),
			dm_bufio_get_block_data(dm_j_buffers[0]), v->dev_block_bytes);
		mintegrity_add_buffers_to_journal(v, sector, dm_buffers, dm_j_buffers,
			0, tag);

		continue;

	bad:
		mintegrity_add_buffers_to_journal(v, sector, dm_buffers, dm_j_buffers,
			-EIO, tag);
		return -EIO;
	}
	BUG_ON(vector != io->io_vec_size);
	BUG_ON(offset);
	// Finished!
	return 0;
}

static void mintegrity_read_work(struct work_struct *w)
{
	int error;
	struct dm_mintegrity_io *io = container_of(w, struct dm_mintegrity_io, work);
	struct dm_mintegrity *v = io->v;
	struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_bio_data_size);

	// Lock down!
	down_read(&(v->lock));
	error = mintegrity_verify_read_io(io);

	if (io->io_vec != io->io_vec_inline)
		mempool_free(io->io_vec, v->vec_mempool);

	// Unlock!
	up_read(&(v->lock));
	bio_endio(bio, error);
}

static void mintegrity_read_end_io(struct bio *bio, int error)
{
	struct dm_mintegrity_io *io = bio->bi_private;

	bio->bi_sector = bio->bi_sector - (io->v->data_start << (io->v->dev_block_bits - SECTOR_SHIFT));
	bio->bi_end_io = io->orig_bi_end_io;
	bio->bi_private = io->orig_bi_private;

	if (error) {
		if (io->io_vec != io->io_vec_inline)
			mempool_free(io->io_vec, io->v->vec_mempool);
		bio_endio(bio, error);
	}

	INIT_WORK(&(io->work), mintegrity_read_work);
	queue_work(io->v->read_wq, &io->work);
}

static void mintegrity_write_work(struct work_struct *w)
{
	int error;
	struct dm_mintegrity_io *io = container_of(w, struct dm_mintegrity_io, work);
	struct dm_mintegrity *v = io->v;
	struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_bio_data_size);

	// Lock down!
	down_write(&(v->lock));
	error = mintegrity_verify_write_io(io);

	if (io->io_vec != io->io_vec_inline)
		mempool_free(io->io_vec, v->vec_mempool);

	// Unlock!
	up_write(&(v->lock));
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
		dm_bufio_prefetch(v->bufio, hash_block_start,
			hash_block_end - hash_block_start + 1);
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
	queue_work(v->read_wq, &pw->work);
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
	bio->bi_bdev = v->dev->bdev;
	bio->bi_sector = mintegrity_map_sector(v, bio->bi_sector);

	if (((unsigned)bio->bi_sector | bio_sectors(bio)) &
	    ((1 << (v->dev_block_bits - SECTOR_SHIFT)) - 1)) {
		DMERR_LIMIT("unaligned io");
		return -EIO;
	}

	if (bio_end_sector(bio) >>
	    (v->dev_block_bits - SECTOR_SHIFT) > v->data_blocks) {
		DMERR_LIMIT("io out of range");
		return -EIO;
	}

	if (bio_data_dir(bio) == WRITE || bio_data_dir(bio) == READ) {
		// Common setup
		io = dm_per_bio_data(bio, ti->per_bio_data_size);
		io->bio = bio;
		io->v = v;
		io->block = bio->bi_sector >> (v->dev_block_bits - SECTOR_SHIFT);
		io->n_blocks = bio->bi_size >> v->dev_block_bits;

		// Why is this here?
		io->io_vec_size = bio_segments(bio);
		if (io->io_vec_size < DM_MINTEGRITY_IO_VEC_INLINE)
			io->io_vec = io->io_vec_inline;
		else
			io->io_vec = mempool_alloc(v->vec_mempool, GFP_NOIO);
		memcpy(io->io_vec, bio_iovec(bio),
			io->io_vec_size * sizeof(struct bio_vec));

		// Prefetch blocks
		mintegrity_submit_prefetch(v, io);

		switch(bio_data_dir(bio)) {
		case WRITE:
			INIT_WORK(&(io->work), mintegrity_write_work);
			queue_work(io->v->write_wq, &io->work);
			break;
		case READ:
			bio->bi_sector = bio->bi_sector + (v->data_start << (v->dev_block_bits - SECTOR_SHIFT));
			io->orig_bi_end_io = bio->bi_end_io;
			io->orig_bi_private = bio->bi_private;
			bio->bi_end_io = mintegrity_read_end_io;
			bio->bi_private = io;
			generic_make_request(bio);
			break;
		}
	} else {
		// Unsupported bio operation
		return -EIO;
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
		for (x = 0; x < v->digest_size; x++)
			DMEMIT("%02x", v->root_digest[x]);
		DMEMIT(" ");
		if (!v->salt_size)
			DMEMIT("-");
		else
			for (x = 0; x < v->salt_size; x++)
				DMEMIT("%02x", v->salt[x]);
		DMEMIT(" %i %i", atomic_read(&v->j_checkpoint_remaining), v->j_blocks_to_free);
		break;
	}
}

static int mintegrity_ioctl(struct dm_target *ti, unsigned cmd,
			unsigned long arg)
{
	struct dm_mintegrity *v = ti->private;
	int r = 0;

	// TODO: Not supported yet - because journal not locked
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

	return fn(ti, v->dev, v->data_start_shift, ti->len, data);
}

static void mintegrity_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct dm_mintegrity *v = ti->private;

	if (limits->logical_block_size < 1 << v->dev_block_bits)
		limits->logical_block_size = 1 << v->dev_block_bits;

	if (limits->physical_block_size < 1 << v->dev_block_bits)
		limits->physical_block_size = 1 << v->dev_block_bits;

	blk_limits_io_min(limits, limits->logical_block_size);
}

static void mintegrity_dtr(struct dm_target *ti)
{
	struct dm_mintegrity *v = ti->private;

	v->committing = 3;
	up(&v->flush_semaphore);
	if (v->j_background_thread)
		kthread_stop(v->j_background_thread);

	if (v->j_flush_thread)
		kthread_stop(v->j_flush_thread);

	if (v->journal_wq) 
		destroy_workqueue(v->journal_wq);

	if (v->write_wq)
		destroy_workqueue(v->write_wq);

	if (v->read_wq)
		destroy_workqueue(v->read_wq);

	if (v->vec_mempool)
		mempool_destroy(v->vec_mempool);

	mintegrity_checkpoint_journal(v, 0, 1);

	dm_bufio_release(v->j_sb_buffer);
	dm_bufio_release(v->j_ds_buffer);

	if (v->bufio)
		dm_bufio_client_destroy(v->bufio);

	kfree(v->hmac_digest);
	kfree(v->inner_pad);
	kfree(v->outer_pad);
	kfree(v->secret);
	kfree(v->salt);
	kfree(v->root_digest);

	if (v->hmac_desc)
		kfree(v->hmac_desc);

	if (v->hmac_tfm)
		crypto_free_shash(v->hmac_tfm);

	if (v->tfm)
		crypto_free_shash(v->tfm);

	kfree(v->hmac_alg_name);
	kfree(v->alg_name);

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
	sector_t reserved;
	// sector_t b;
	char dummy;

	// Allocate struct dm_mintegrity for this device mapper instance
	v = kzalloc(sizeof(struct dm_mintegrity), GFP_KERNEL);
	if (!v) {
		ti->error = "Cannot allocate mintegrity structure";
		return -ENOMEM;
	}
	ti->private = v;
	v->ti = ti;

	// Check that dmsetup table is writeable
	// TODO: read only mode
	if (!(dm_table_get_mode(ti->table) & FMODE_WRITE)) {
		ti->error = "Device must be writeable!";
		r = -EINVAL;
		goto bad;
	}

	// Check argument count
	if (argc != 10) {
		ti->error = "Invalid argument count: exactly 10 arguments required";
		r = -EINVAL;
		goto bad;
	}

	// argv[0] <data device>
	r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &v->dev);
	if (r) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	// argv[1] <block size>
	if (sscanf(argv[1], "%u%c", &num, &dummy) != 1 ||
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
	if (sscanf(argv[2], "%llu%c", &num_ll, &dummy) != 1){
		ti->error = "Invalid number of hash blocks";
		r = -EINVAL;
		goto bad;
	}
	v->hash_blocks = num_ll;
	// 1, because skip superblock
	v->hash_start = 1;

	// argv[3] <number of journal blocks>
	if (sscanf(argv[3], "%llu%c", &num_ll, &dummy) != 1){
		ti->error = "Invalid number of journal blocks";
		r = -EINVAL;
		goto bad;
	}
	v->journal_blocks = num_ll;
	v->journal_start = v->hash_start + v->hash_blocks;

	// argv[4] <number of data blocks>
	if (sscanf(argv[4], "%llu%c", &num_ll, &dummy) != 1 ||
	    (sector_t)(num_ll << (v->dev_block_bits - SECTOR_SHIFT))
	    >> (v->dev_block_bits - SECTOR_SHIFT) != num_ll) {
		ti->error = "Invalid data blocks";
		r = -EINVAL;
		goto bad;
	}
	v->data_blocks = num_ll;
	v->data_start = v->journal_start + v->journal_blocks;

	// Check that device is long enough
	if (ti->len > (v->data_blocks << (v->dev_block_bits - SECTOR_SHIFT))) {
		ti->error = "Data device is too small";
		r = -EINVAL;
		goto bad;
	}

	// argv[5] <data hash type>
	v->alg_name = kstrdup(argv[5], GFP_KERNEL);
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
	if (strlen(argv[6]) != v->digest_size * 2 ||
	    hex2bin(v->root_digest, argv[6], v->digest_size)) {
		ti->error = "Invalid root digest";
		r = -EINVAL;
		goto bad;
	}

	// argv[7] <salt>
	if (strcmp(argv[7], "-")) { // no salt if "-"
		v->salt_size = strlen(argv[7]) / 2;
		v->salt = kmalloc(v->salt_size, GFP_KERNEL);
		if (!v->salt) {
			ti->error = "Cannot allocate salt";
			r = -ENOMEM;
			goto bad;
		}
		if (strlen(argv[7]) != v->salt_size * 2 ||
		    hex2bin(v->salt, argv[7], v->salt_size)) {
			ti->error = "Invalid salt";
			r = -EINVAL;
			goto bad;
		}
	}

	// argv[8] <hmac hash type>
	v->hmac_alg_name = kstrdup(argv[8], GFP_KERNEL);
	if (!v->hmac_alg_name) {
		ti->error = "Cannot allocate algorithm name";
		r = -ENOMEM;
		goto bad;
	}

	// Allocate a crypto hash object based on algorithm name
	v->hmac_tfm = crypto_alloc_shash(v->hmac_alg_name, 0, 0);
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
	v->hmac_desc->tfm = v->hmac_tfm;
	v->hmac_desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	// argv[9] <hmac secret>
	v->secret_size = strlen(argv[9]) / 2;
	v->secret = kmalloc(v->secret_size, GFP_KERNEL);
	if (!v->secret) {
		ti->error = "Cannot allocate secret";
		r = -ENOMEM;
		goto bad;
	}
	if (strlen(argv[9]) != v->secret_size * 2 ||
	    hex2bin(v->secret, argv[9], v->secret_size)) {
		ti->error = "Invalid secret";
		r = -EINVAL;
		goto bad;
	}

	// Precompute values for HMAC computation - RFC 2104
	v->outer_pad = kzalloc(v->hmac_digest_size, GFP_KERNEL);
	if (!v->outer_pad) {
		ti->error = "Cannot allocate outer pad";
		r = -ENOMEM;
		goto bad;
	}
	v->inner_pad = kzalloc(v->hmac_digest_size, GFP_KERNEL);
	if (!v->inner_pad) {
		ti->error = "Cannot allocate inner pad";
		r = -ENOMEM;
		goto bad;
	}
	v->hmac_digest = kzalloc(v->hmac_digest_size, GFP_KERNEL);
	if (!v->hmac_digest) {
		ti->error = "Cannot allocate hmac digest";
		r = -ENOMEM;
		goto bad;
	}

	// len(key) > len(hash) --> key = hash(key)
	if (v->secret_size > v->hmac_digest_size) {
		r = crypto_shash_init(v->hmac_desc);
		if (r < 0) {
			ti->error = "crypto_shash_init failed";
			r = -EINVAL;
			goto bad;
		}
		r = crypto_shash_update(v->hmac_desc, v->secret, v->secret_size);
		if (r < 0) {
			ti->error = "crypto_shash_update failed";
			r = -EINVAL;
			goto bad;
		}
		r = crypto_shash_final(v->hmac_desc, v->hmac_digest);
		if (r < 0) {
			ti->error = "crypto_shash_final failed";
			r = -EINVAL;
			return r;
		}
		for (i = 0; i < v->hmac_digest_size; i++) {
			v->outer_pad[i] = 0x5c ^ v->hmac_digest[i];
			v->inner_pad[i] = 0x36 ^ v->hmac_digest[i];
		}
	} else {
		for (i = 0; i < v->secret_size; i++) {
			v->outer_pad[i] = 0x5c ^ v->secret[i];
			v->inner_pad[i] = 0x36 ^ v->secret[i];
		}
		for (i = v->secret_size; i < v->hmac_digest_size; i++) {
			v->outer_pad[i] = 0x5c ^ 0x00;
			v->inner_pad[i] = 0x36 ^ 0x00;
		}
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

	// Number of necessary reserved buffers
	reserved = 4096;
	// b = v->data_blocks;
	// TODO: this again
	// Min of number of hash blocks in level and numbe of transactions
	// for (i = 0; i < v->levels; i++) {
	// 	b = (b == 0 ? b : (1 + ((b - 1) / (v->dev_block_bytes / v->digest_size))));
	// 	reserved += min(b, (v->journal_blocks - 1) / 2);
	// }
	// One data block per transaction
	// reserved += (v->journal_blocks - 1) / 2;
	// Journal blocks
	// reserved += v->journal_blocks;
	// One for each read operation
	// reserved += num_online_cpus();
	// One for journal superblock
	// reserved += 1;

	// Open device mapper buffered IO client
	v->bufio = dm_bufio_client_create(v->dev->bdev, 1 << v->dev_block_bits,
		reserved, sizeof(struct buffer_aux), dm_bufio_alloc_callback, NULL,
		dm_bufio_endio_callback);
	if (IS_ERR(v->bufio)) {
		ti->error = "Cannot initialize dm-bufio";
		r = PTR_ERR(v->bufio);
		v->bufio = NULL;
		goto bad;
	}

	if (dm_bufio_get_device_size(v->bufio) < (v->hash_blocks + v->journal_blocks
		+ v->data_blocks)) {
		ti->error = "Device is too small";
		r = -E2BIG;
		goto bad;
	}

	v->vec_mempool = mempool_create_kmalloc_pool(DM_MINTEGRITY_MEMPOOL_SIZE,
					BIO_MAX_PAGES * sizeof(struct bio_vec));
	if (!v->vec_mempool) {
		ti->error = "Cannot allocate vector mempool";
		r = -ENOMEM;
		goto bad;
	}

	/* Initialize lock for IO operations */
	init_rwsem(&(v->lock));
	init_rwsem(&(v->j_lock));
	init_rwsem(&(v->j_checkpoint_lock));
	init_rwsem(&(v->j_commit_finish_lock));
	sema_init(&v->flush_semaphore, 0);
	v->commit_count = 0;

	// Read queue
	/* WQ_UNBOUND greatly improves performance when running on ramdisk */
	v->read_wq = alloc_workqueue("kmintegrityd_read",
		WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND, 3);
	if (!v->read_wq) {
		ti->error = "Cannot allocate read workqueue";
		r = -ENOMEM;
		goto bad;
	}

	// Write queue
	/* WQ_UNBOUND greatly improves performance when running on ramdisk */
	v->write_wq = alloc_workqueue("kmintegrityd_write",
		WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND, num_online_cpus());
	if (!v->write_wq) {
		ti->error = "Cannot allocate write workqueue";
		r = -ENOMEM;
		goto bad;
	}

	// Journal queue
	/* WQ_UNBOUND greatly improves performance when running on ramdisk */
	v->journal_wq = alloc_workqueue("kmintegrityd_journal",
		WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND, num_online_cpus());
	if (!v->journal_wq) {
		ti->error = "Cannot allocate write workqueue";
		r = -ENOMEM;
		goto bad;
	}

	r = mintegrity_recover_journal(v);
	if (r < 0) {
		ti->error = "Could not recover journal";
		r = -EIO;
		goto bad;
	}

	ti->per_bio_data_size = roundup(sizeof(struct dm_mintegrity_io) +
		v->shash_descsize + v->digest_size * 2 + (v->levels + 1 + v->j_bpt) *
		sizeof(struct dm_buffer*), __alignof__(struct dm_mintegrity_io));

	v->j_background_thread = kthread_run(mintegrity_background_journal_thread,
		v, "mintegrity_background_journal");
	if (IS_ERR(v->j_background_thread)) {
		ti->error = "Could not allocate background journal thread";
		r = -ENOMEM;
		goto bad;
	}

	v->j_flush_thread = kthread_run(mintegrity_background_flush_thread,
		v, "mintegrity_flush_journal");
	if (IS_ERR(v->j_flush_thread)) {
		ti->error = "Could not allocate background flush thread";
		r = -ENOMEM;
		goto bad;
	}

	printk(KERN_CRIT "Levels: %d", v->levels);

	v->created = 1;
	return 0;

bad:
	mintegrity_dtr(ti);
	return r;
}

// Struct for registering mintegrity
static struct target_type mintegrity_target = {
	.name		= "mintegrity",
	.version	= {1, 2, 0},
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
