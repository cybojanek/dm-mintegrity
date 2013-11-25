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

#define DM_MSG_PREFIX			"mintegrity"

#define DM_MINTEGRITY_IO_VEC_INLINE		16
#define DM_MINTEGRITY_MEMPOOL_SIZE		4
#define DM_MINTEGRITY_DEFAULT_PREFETCH_SIZE	262144

#define DM_MINTEGRITY_MAX_LEVELS		63

static unsigned dm_mintegrity_prefetch_cluster = DM_MINTEGRITY_DEFAULT_PREFETCH_SIZE;

module_param_named(prefetch_cluster, dm_mintegrity_prefetch_cluster, uint, S_IRUGO | S_IWUSR);

struct mintegrity_journal_superblock {
	char magic[16];                 /**< 0x6c696c796d756666696e000000000000 */
	uint32_t transaction_capacity;  /**< Number of max transaction */
	uint32_t transaction_fill;      /**< Number of transactions in journal */
	uint32_t block_size;            /**< Size of a single block */
	uint32_t num_blocks;            /**< Number of block in this journal (including superblock) */
	uint16_t hash_levels;           /**< Number of hash levels */
	uint16_t hash_bytes;            /**< Number of bytes in a hash */
	char state;                     /**< Clean, Committing */
	char hmac[128];                 /**< hmac for flush update */
};

struct dm_mintegrity {
	struct dm_dev *data_dev;
	struct dm_dev *hash_dev;
	struct dm_target *ti;
	struct dm_bufio_client *bufio;

	char *alg_name;
	struct crypto_shash *tfm;
	u8 *root_digest;	/* digest of the root block */
	u8 *salt;		/* salt: its size is salt_size */
	unsigned salt_size;

	unsigned digest_size;	/* digest size for the current hash algorithm */
	unsigned shash_descsize;/* the size of temporary space for crypto */
	int hash_failed;	/* set to 1 if hash of any block failed */

	sector_t hash_start;	/* hash start in blocks */
	sector_t journal_start;	/* journal start in blocks */
	sector_t data_start;	/* data offset in 512-byte sectors */

	sector_t hash_blocks;	/* the number of hash blocks */
	sector_t journal_blocks;/* the number of journal blocks */
	sector_t data_blocks;	/* the number of data blocks */

	unsigned char dev_block_bits;	/* log2(blocksize) */
	unsigned char hash_per_block_bits;	/* log2(hashes in hash block) */

	unsigned char levels;	/* the number of tree levels */

	mempool_t *vec_mempool;	/* mempool of bio vector */
	mempool_t *hb_mempool;  /* mempool for hash block writebacks */

	struct workqueue_struct *wait_read_wq; /* workqueue for read lock */
	struct workqueue_struct *read_wq;      /* workqueue for processing reads */
	struct workqueue_struct *write_wq;     /* workqeue for processing writes */
	struct rw_semaphore lock;              /* read/write lock */

	struct mintegrity_journal_superblock journal_superblock;

	/* starting blocks for each tree level. 0 is the lowest level. */
	sector_t hash_level_block[DM_MINTEGRITY_MAX_LEVELS];
};

struct dm_mintegrity_io {
	struct dm_mintegrity *v;

	/* original values of bio->bi_end_io and bio->bi_private */
	bio_end_io_t *orig_bi_end_io;
	void *orig_bi_private;

	sector_t block;
	unsigned n_blocks;

	/* saved bio vector */
	struct bio *bio;
	struct bio_vec *io_vec;
	u8 *hb_vec;
	unsigned io_vec_size;

	struct work_struct work;

	/* A space for short vectors; longer vectors are allocated separately. */
	struct bio_vec io_vec_inline[DM_MINTEGRITY_IO_VEC_INLINE];

	/*
	 * Three variably-size fields follow this struct:
	 *
	 * u8 hash_desc[v->shash_descsize];
	 * u8 real_digest[v->digest_size];
	 * u8 want_digest[v->digest_size];
	 *
	 * To access them use: io_hash_desc(), io_real_digest() and io_want_digest().
	 */
};

struct dm_mintegrity_prefetch_work {
	struct work_struct work;
	struct dm_mintegrity *v;
	sector_t block;
	unsigned n_blocks;
};

static struct shash_desc *io_hash_desc(struct dm_mintegrity *v, struct dm_mintegrity_io *io)
{
	return (struct shash_desc *)(io + 1);
}

static u8 *io_real_digest(struct dm_mintegrity *v, struct dm_mintegrity_io *io)
{
	return (u8 *)(io + 1) + v->shash_descsize;
}

static u8 *io_want_digest(struct dm_mintegrity *v, struct dm_mintegrity_io *io)
{
	return (u8 *)(io + 1) + v->shash_descsize + v->digest_size;
}

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
struct buffer_aux {
	int hash_verified;
};

/*
 * Initialize struct buffer_aux for a freshly created buffer.
 */
static void dm_bufio_alloc_callback(struct dm_buffer *buf)
{
	struct buffer_aux *aux = dm_bufio_get_aux_data(buf);

	aux->hash_verified = 0;
}

/*
 * What do we want to do on a write callback ??
 */
 static void dm_bufio_write_callback(struct dm_buffer *buf)
 {
	// ???
 }

/*
 * Translate input sector number to the sector number on the target device.
 */
static sector_t mintegrity_map_sector(struct dm_mintegrity *v, sector_t bi_sector)
{
	return v->data_start + dm_target_offset(v->ti, bi_sector);
}

/*
 * Return hash position of a specified block at a specified tree level
 * (0 is the lowest level).
 * The lowest "hash_per_block_bits"-bits of the result denote hash position
 * inside a hash block. The remaining bits denote location of the hash block.
 */
static sector_t mintegrity_position_at_level(struct dm_mintegrity *v, sector_t block,
					 int level)
{
	return block >> (level * v->hash_per_block_bits);
}

static void mintegrity_hash_at_level(struct dm_mintegrity *v, sector_t block, int level,
				 sector_t *hash_block, unsigned *offset)
{
	sector_t position = mintegrity_position_at_level(v, block, level);
	unsigned idx;

	*hash_block = v->hash_level_block[level] + (position >> v->hash_per_block_bits);

	if (!offset)
		return;

	idx = position & ((1 << v->hash_per_block_bits) - 1);
	*offset = idx << (v->dev_block_bits - v->hash_per_block_bits);
}

/*
 * Calculate hash of buffer and put it in io_real_digest
 */
static int mintegrity_buffer_hash(struct dm_mintegrity_io *io, const u8 *data, unsigned int len)
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
 * Verify hash of a metadata block pertaining to the specified data block
 * ("block" argument) at a specified level ("level" argument).
 *
 * On successful return, io_want_digest(v, io) contains the hash value for
 * a lower tree level or for the data block (if we're at the lowest leve).
 *
 * If "skip_unverified" is true, unverified buffer is skipped and 1 is returned.
 * If "skip_unverified" is false, unverified buffer is hashed and verified
 * against current value of io_want_digest(v, io).
 */
static int mintegrity_verify_level(struct dm_mintegrity_io *io, sector_t block,
			       int level, bool skip_unverified, bool get_data, char *level_data)
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
		struct shash_desc *desc;
		u8 *result;

		if (skip_unverified) {
			r = 1;
			goto release_ret_r;
		}

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

		r = crypto_shash_update(desc, data, 1 << v->dev_block_bits);
		if (r < 0) {
			DMERR("crypto_shash_update failed: %d", r);
			goto release_ret_r;
		}

		result = io_real_digest(v, io);
		r = crypto_shash_final(desc, result);
		if (r < 0) {
			DMERR("crypto_shash_final failed: %d", r);
			goto release_ret_r;
		}
		if (unlikely(memcmp(result, io_want_digest(v, io), v->digest_size))) {
			DMERR_LIMIT("metadata block %llu is corrupted",
				(unsigned long long)hash_block);
			v->hash_failed = 1;
			r = -EIO;
			goto release_ret_r;
		} else {
			// ignore this for now and keep it at 0
			aux->hash_verified = 0;
		}
	}
	// Return back the whole block we read and verified
	if(get_data){
		memcpy(level_data, data, 1 << v->dev_block_bits);
	}

	data += offset;

	memcpy(io_want_digest(v, io), data, v->digest_size);


	dm_bufio_release(buf);
	return 0;

release_ret_r:
	dm_bufio_release(buf);

	return r;
}

/*
 * Verify one "dm_mintegrity_io" structure.
 */
static int mintegrity_verify_io(struct dm_mintegrity_io *io)
{
	struct dm_mintegrity *v = io->v;
	unsigned b;
	int i;
	unsigned vector = 0, offset = 0;

	for (b = 0; b < io->n_blocks; b++) {
		struct shash_desc *desc;
		u8 *result;
		int r;
		unsigned todo;

		if (likely(v->levels)) {
			/*
			 * First, we try to get the requested hash for
			 * the current block. If the hash block itself is
			 * verified, zero is returned. If it isn't, this
			 * function returns 0 and we fall back to whole
			 * chain verification.
			 */
			int r = mintegrity_verify_level(io, io->block + b, 0, true,
				false, NULL);
			if (likely(!r))
				goto test_block_hash;
			if (r < 0)
				return r;
		}

		memcpy(io_want_digest(v, io), v->root_digest, v->digest_size);
		// print_hex_dump(KERN_CRIT, "root: ", DUMP_PREFIX_NONE, 16, 1, v->root_digest, v->digest_size, false);

		for (i = v->levels - 1; i >= 0; i--) {
			int r = mintegrity_verify_level(io, io->block + b, i, false,
				false, NULL);
			if (unlikely(r))
				return r;
		}

test_block_hash:
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
	BUG_ON(vector != io->io_vec_size);
	BUG_ON(offset);

	return 0;
}

/*
 * End one "io" structure with a given error.
 */
static void mintegrity_finish_write_io(struct dm_mintegrity_io *io, int error)
{
	struct dm_mintegrity *v = io->v;
	struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_bio_data_size);

	bio->bi_end_io = io->orig_bi_end_io;
	bio->bi_private = io->orig_bi_private;

	if (io->io_vec != io->io_vec_inline)
		mempool_free(io->io_vec, v->vec_mempool);

	mempool_free(io->hb_vec, v->hb_mempool);

	// Unlock before end of io
	up_write(&(io->v->lock));
	bio_endio(bio, error);
}

/*
 * End one "io" structure with a given error.
 */
static void mintegrity_finish_read_io(struct dm_mintegrity_io *io, int error)
{
	struct dm_mintegrity *v = io->v;
	struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_bio_data_size);

	bio->bi_end_io = io->orig_bi_end_io;
	bio->bi_private = io->orig_bi_private;

	if (io->io_vec != io->io_vec_inline)
		mempool_free(io->io_vec, v->vec_mempool);

	// Unlock before end of io
	up_read(&(io->v->lock));
	bio_endio(bio, error);
}

static void mintegrity_write_work(struct work_struct *w)
{
	struct dm_mintegrity_io *io = container_of(w, struct dm_mintegrity_io, work);
	struct dm_mintegrity *v = io->v;
	unsigned b;
	int i;
	unsigned vector = 0, offset = 0;

	// Lock down!
	down_write(&(v->lock));

	for(b = 0; b < io->n_blocks; b++){
		struct shash_desc *desc;
		int r;
		u8 * result;
		unsigned todo;

		sector_t hash_block;
		struct dm_buffer *buf;
		u8 *data;

		// The io digest we want is the root
		memcpy(io_want_digest(v, io), v->root_digest, v->digest_size);

		// Read levels, TOP DOWN and compare to io want, which is set after
		// every successive read
		for (i = v->levels - 1; i >= 0; i--) {
			int r = mintegrity_verify_level(io, io->block + b, i, false, true,
				io->hb_vec + (1 << v->dev_block_bits) * i);
			if (unlikely(r)){
				mintegrity_finish_write_io(io, -EIO);
				return;
			}
		}

		// Compute hash
		desc = io_hash_desc(v, io);  // io hash description field for io request
		desc->tfm = v->tfm;  // hash function
		desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
		// Init hash
		r = crypto_shash_init(desc);
		if (r < 0) {
			DMERR("crypto_shash_init failed: %d", r);
			mintegrity_finish_write_io(io, -EIO);
			return;
		}
		// Update with salt
		r = crypto_shash_update(desc, v->salt, v->salt_size);
		if (r < 0) {
			DMERR("crypto_shash_update failed: %d", r);
			mintegrity_finish_write_io(io, -EIO);
			return;
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
				mintegrity_finish_write_io(io, -EIO);
				return;
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
			mintegrity_finish_write_io(io, -EIO);
			return;
		}

		// Copy data hash into first level
		// Hash offset
		mintegrity_hash_at_level(v, io->block + b, 0, &hash_block, &offset);
		// Set hash for first level
		memcpy(io->hb_vec + offset, result, v->digest_size);
		// Write block to disk
		// TODO: remove bufio
		data = dm_bufio_read(v->bufio, hash_block, &buf);
		memcpy(data, io->hb_vec, (1 << v->dev_block_bits));
		dm_bufio_mark_buffer_dirty(buf);
		dm_bufio_release(buf);

		// Write things back bottom up
		for (i = 1; i < v->levels; i++){
			// Get offset for level
			mintegrity_hash_at_level(v, io->block + b, i, &hash_block, &offset);
			// Calculate hash for level below
			r = mintegrity_buffer_hash(io, io->hb_vec + (1 << v->dev_block_bits) * (i-1), (1 << v->dev_block_bits));
			if(r < 0) {
				DMERR("failed to calcualte write buffer hash for level");
				mintegrity_finish_write_io(io, -EIO);
			}
			result = io_real_digest(v, io);
			// Copy hash into current level
			memcpy(io->hb_vec + ((1 << v->dev_block_bits) * i) + offset, result, v->digest_size);
			// Write block to disk
			// TODO: remove bufio
			data = dm_bufio_read(v->bufio, hash_block, &buf);
			memcpy(data, io->hb_vec + ((1 << v->dev_block_bits) * i), (1 << v->dev_block_bits));
			dm_bufio_mark_buffer_dirty(buf);
			dm_bufio_release(buf);
		}
		// Update root merkle tree hash
		r = mintegrity_buffer_hash(io, io->hb_vec + (1 << v->dev_block_bits) * (v->levels - 1), (1 << v->dev_block_bits));
		if (r < 0) {
			DMERR("failed to calcualte write buffer hash for level");
			mintegrity_finish_write_io(io, -EIO);
		}
		result = io_real_digest(v, io);
		memcpy(v->root_digest, result, v->digest_size);
	}
	// Run BIO request writing data to data device
	generic_make_request(io->bio);
}

static void mintegrity_read_work(struct work_struct *w)
{
	struct dm_mintegrity_io *io = container_of(w, struct dm_mintegrity_io, work);
	mintegrity_finish_read_io(io, mintegrity_verify_io(io));
}

static void mintegrity_end_write_io(struct bio *bio, int error)
{
	struct dm_mintegrity_io *io = bio->bi_private;
	mintegrity_finish_write_io(io, error);
}

static void mintegrity_end_read_io(struct bio *bio, int error)
{
	struct dm_mintegrity_io *io = bio->bi_private;

	if (error) {
		mintegrity_finish_read_io(io, error);
		return;
	}

	INIT_WORK(&io->work, mintegrity_read_work);
	queue_work(io->v->read_wq, &io->work);
}

static void mintegrity_read_wait(struct work_struct *w)
{
	struct dm_mintegrity_io *io = container_of(w, struct dm_mintegrity_io, work);
	struct dm_mintegrity *v = io->v;
	down_read(&(v->lock));
	generic_make_request(io->bio);
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
		mintegrity_hash_at_level(v, pw->block + pw->n_blocks - 1, i, &hash_block_end, NULL);
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

static void mintegrity_submit_prefetch(struct dm_mintegrity *v, struct dm_mintegrity_io *io)
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


	bio->bi_bdev = v->data_dev->bdev;
	bio->bi_sector = mintegrity_map_sector(v, bio->bi_sector);

	if (((unsigned)bio->bi_sector | bio_sectors(bio)) &
	    ((1 << (v->dev_block_bits - SECTOR_SHIFT)) - 1)) {
		DMERR_LIMIT("unaligned io");
		return -EIO;
	}

	if (bio_end_sector(bio) >>
	    (v->dev_block_bits - SECTOR_SHIFT) > v->data_blocks + (v->data_start * 8)) {
		DMERR_LIMIT("io out of range");
		return -EIO;
	}

	if (bio_data_dir(bio) == WRITE) {
		io = dm_per_bio_data(bio, ti->per_bio_data_size);
		io->bio = bio;
		io->v = v;
		io->orig_bi_end_io = bio->bi_end_io;
		io->orig_bi_private = bio->bi_private;
		bio->bi_private = io;
		bio->bi_end_io = mintegrity_end_write_io;
		io->block = bio->bi_sector >> (v->dev_block_bits - SECTOR_SHIFT);
		io->n_blocks = bio->bi_size >> v->dev_block_bits;
		// Copy bio buffers?
		io->io_vec_size = bio_segments(bio);
		if (io->io_vec_size < DM_MINTEGRITY_IO_VEC_INLINE)
			io->io_vec = io->io_vec_inline;
		else
			io->io_vec = mempool_alloc(v->vec_mempool, GFP_NOIO);
		memcpy(io->io_vec, bio_iovec(bio),
		       io->io_vec_size * sizeof(struct bio_vec));
		io->hb_vec = mempool_alloc(v->hb_mempool, GFP_NOIO);
		/* Queue up write */
		INIT_WORK(&(io->work), mintegrity_write_work);
		queue_work(io->v->write_wq, &io->work);
	}

	if(bio_data_dir(bio) == READ) {
		/* Prepare bio for work */
		io = dm_per_bio_data(bio, ti->per_bio_data_size);
		io->bio = bio;
		io->v = v;
		io->orig_bi_end_io = bio->bi_end_io;
		io->orig_bi_private = bio->bi_private;
		io->block = bio->bi_sector >> (v->dev_block_bits - SECTOR_SHIFT);
		io->n_blocks = bio->bi_size >> v->dev_block_bits;

		bio->bi_private = io;
		bio->bi_end_io = mintegrity_end_read_io;
		io->io_vec_size = bio_segments(bio);
		if (io->io_vec_size < DM_MINTEGRITY_IO_VEC_INLINE)
			io->io_vec = io->io_vec_inline;
		else
			io->io_vec = mempool_alloc(v->vec_mempool, GFP_NOIO);
		memcpy(io->io_vec, bio_iovec(bio),
		       io->io_vec_size * sizeof(struct bio_vec));

		// Disable prefetching for now
		// mintegrity_submit_prefetch(v, io);
		// Submit to queue to wait for lock
		INIT_WORK(&(io->work), mintegrity_read_wait);
		queue_work(io->v->wait_read_wq, &io->work);
		// Make request after getting read lock in read_wait instead of here
		// generic_make_request(bio);
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
		DMEMIT("%s %s %u %u %llu %llu %s ",
			v->data_dev->name,
			v->hash_dev->name,
			1 << v->dev_block_bits,
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
		break;
	}
}

static int mintegrity_ioctl(struct dm_target *ti, unsigned cmd,
			unsigned long arg)
{
	struct dm_mintegrity *v = ti->private;
	int r = 0;

	if (v->data_start ||
	    ti->len != i_size_read(v->data_dev->bdev->bd_inode) >> SECTOR_SHIFT)
		r = scsi_verify_blk_ioctl(NULL, cmd);

	return r ? : __blkdev_driver_ioctl(v->data_dev->bdev, v->data_dev->mode,
				     cmd, arg);
}

static int mintegrity_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			struct bio_vec *biovec, int max_size)
{
	struct dm_mintegrity *v = ti->private;
	struct request_queue *q = bdev_get_queue(v->data_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = v->data_dev->bdev;
	bvm->bi_sector = mintegrity_map_sector(v, bvm->bi_sector);

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int mintegrity_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct dm_mintegrity *v = ti->private;

	return fn(ti, v->data_dev, v->data_start, ti->len, data);
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

	if (v->write_wq)
		destroy_workqueue(v->write_wq);

	if (v->wait_read_wq)
		destroy_workqueue(v->wait_read_wq);

	if (v->read_wq)
		destroy_workqueue(v->read_wq);

	if (v->hb_mempool)
		mempool_destroy(v->hb_mempool);

	if (v->vec_mempool)
		mempool_destroy(v->vec_mempool);

	if (v->bufio) {
			dm_bufio_write_dirty_buffers(v->bufio);
		dm_bufio_client_destroy(v->bufio);
	}

	kfree(v->salt);
	kfree(v->root_digest);

	if (v->tfm)
		crypto_free_shash(v->tfm);

	kfree(v->alg_name);

	if (v->hash_dev)
		dm_put_device(ti, v->hash_dev);

	if (v->data_dev)
		dm_put_device(ti, v->data_dev);

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
 * TODO: change salt support to this
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
	struct dm_buffer *buf;
	u8 *data;

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
		ti->error = "Invalid argument count: exactly 11 arguments required";
		r = -EINVAL;
		goto bad;
	}

	// argv[0] <data device>
	r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &v->data_dev);
	if (r) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	// SAME DEVICE: what happens now?
	r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &v->hash_dev);
	if (r) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	// argv[1] <block size>
	if (sscanf(argv[1], "%u%c", &num, &dummy) != 1 ||
	    !num || (num & (num - 1)) ||
	    num < bdev_logical_block_size(v->data_dev->bdev) ||
	    num > PAGE_SIZE) {
		ti->error = "Invalid data device block size";
		r = -EINVAL;
		goto bad;
	}
	v->dev_block_bits = __ffs(num);

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
	// TODO: struct says this is in 512 byte sectors...
	v->data_start = (v->journal_start + v->journal_blocks) * 8;

	// Check that device is long enough
	// TODO: adjust for jb and hash blocks
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

	// TODO - check hash on hash device when mounting
	// not just wether its hex and of correct size
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

	// Compute start of each hash level
	v->hash_per_block_bits =
		__fls((1 << v->dev_block_bits) / v->digest_size);

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

	// Open device mapper buffered IO client
	v->bufio = dm_bufio_client_create(v->hash_dev->bdev,
		1 << v->dev_block_bits, 1, sizeof(struct buffer_aux), // TODO: reserved count: levels + num online cpus * ?
		dm_bufio_alloc_callback, dm_bufio_write_callback);
	if (IS_ERR(v->bufio)) {
		ti->error = "Cannot initialize dm-bufio";
		r = PTR_ERR(v->bufio);
		v->bufio = NULL;
		goto bad;
	}

	if (dm_bufio_get_device_size(v->bufio) < (v->hash_blocks + v->journal_blocks
		+ v->data_blocks)) {
		ti->error = "Hash device is too small";
		r = -E2BIG;
		goto bad;
	}

	/** Journal setup **/
	data = dm_bufio_read(v->bufio, v->journal_start, &buf);
	if (unlikely(IS_ERR(data))) {
		ti->error = "Failed to read journal superblock";
		r = -EINVAL;
		goto bad;
	}
	memcpy(&v->journal_superblock, data, sizeof(struct mintegrity_journal_superblock));
	dm_bufio_release(buf);

	if(v->journal_superblock.state != 0){
		printk("NEED TO CLEAN UP JOURNAL AND RECOVER HMAC");
	}


	ti->per_bio_data_size = roundup(sizeof(struct dm_mintegrity_io) + v->shash_descsize + v->digest_size * 2, __alignof__(struct dm_mintegrity_io));

	v->vec_mempool = mempool_create_kmalloc_pool(DM_MINTEGRITY_MEMPOOL_SIZE,
					BIO_MAX_PAGES * sizeof(struct bio_vec));
	if (!v->vec_mempool) {
		ti->error = "Cannot allocate vector mempool";
		r = -ENOMEM;
		goto bad;
	}

	// TODO: should this really be here? mempool for write hashes
	v->hb_mempool = mempool_create_kmalloc_pool(DM_MINTEGRITY_MEMPOOL_SIZE,
					v->levels * (1 << v->dev_block_bits));
	if (!v->hb_mempool){
		ti->error = "Cannot allocate hash block mempool";
		r = -ENOMEM;
		goto bad;
	}

	/* Initialize lock for IO operations */
	init_rwsem(&(v->lock));

	// Read queue
	/* WQ_UNBOUND greatly improves performance when running on ramdisk */
	v->read_wq = alloc_workqueue("kmintegrityd_read", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND, num_online_cpus());
	if (!v->read_wq) {
		ti->error = "Cannot allocate read workqueue";
		r = -ENOMEM;
		goto bad;
	}

	// Wait queue
	v->wait_read_wq = alloc_workqueue("kmintegrityd_wait", WQ_MEM_RECLAIM | WQ_UNBOUND, num_online_cpus());
	if (!v->wait_read_wq) {
		ti->error = "Cannot allocate wait workqueue";
		r = -ENOMEM;
		goto bad;
	}

	// Write queue
	v->write_wq = alloc_workqueue("kmintegrityd_write", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND, num_online_cpus());
	if (!v->write_wq) {
		ti->error = "Cannot allocate write workqueue";
		r = -ENOMEM;
		goto bad;
	}

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
