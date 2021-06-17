/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@lougher.demon.co.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * block.c
 */

/*
 * This file implements the low-level routines to read and decompress
 * datablocks and metadata blocks.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/zlib.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs_fs_i.h"
#include "squashfs.h"

/*
 * Read the metadata block length, this is stored in the first two
 * bytes of the metadata block.
 */
static struct buffer_head *get_block_length(struct super_block *sb,
			u64 *cur_index, int *offset, int *length)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	struct buffer_head *bh;

	bh = sb_bread(sb, *cur_index);
	if (bh == NULL)
		return NULL;

	if (msblk->devblksize - *offset == 1) {
		*length = (unsigned char) bh->b_data[*offset];
		put_bh(bh);
		bh = sb_bread(sb, ++(*cur_index));
		if (bh == NULL)
			return NULL;
		*length |= (unsigned char) bh->b_data[0] << 8;
		*offset = 1;
	} else {
		*length = (unsigned char) bh->b_data[*offset] |
			(unsigned char) bh->b_data[*offset + 1] << 8;
		*offset += 2;
	}

	return bh;
}
#ifdef CONFIG_SQUASHFS_LINEAR
static int get_block_length_linear(struct super_block *sb,
			u64 *cur_index, int *offset, int *length)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	char *data = squashfs_linear_read(sb, *cur_index * msblk->devblksize,
					  msblk->devblksize);

	*length = (unsigned char) data[*offset] |
		(unsigned char) data[*offset + 1] << 8;
	*offset += 2;

	return 1;
}

/*
 * Return a pointer to the block in the linearly addressed squashfs image.
 */
void *squashfs_linear_read(struct super_block *sb, unsigned int offset,
			unsigned int len)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;

	if (!len)
		return NULL;

	return (__force void *)msblk->linear_virt_addr + offset;
}
#endif /* CONFIG_SQUASHFS_LINEAR */

/*
 * Read and decompress a metadata block or datablock.  Length is non-zero
 * if a datablock is being read (the size is stored elsewhere in the
 * filesystem), otherwise the length is obtained from the first two bytes of
 * the metadata block.  A bit in the length field indicates if the block
 * is stored uncompressed in the filesystem (usually because compression
 * generated a larger block - this does occasionally happen with zlib).
 */
int squashfs_read_data(struct super_block *sb, void **buffer, u64 index,
			int length, u64 *next_index, int srclength, int pages)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	struct buffer_head **bh;
	int offset = index & ((1 << msblk->devblksize_log2) - 1);
	u64 cur_index = index >> msblk->devblksize_log2;
	int bytes, compressed, b = 0, k = 0, page = 0, avail;
#ifdef CONFIG_SQUASHFS_LINEAR
	char *c_buffer = NULL;
#endif


#ifdef CONFIG_SQUASHFS_LINEAR
	if (LINEAR(msblk))
		bh = NULL;
	else {
		bh = kcalloc((msblk->block_size >> msblk->devblksize_log2) + 1,
					sizeof(*bh), GFP_KERNEL);
		if (bh == NULL)
			return -ENOMEM;
	}
#else
	bh = kcalloc((msblk->block_size >> msblk->devblksize_log2) + 1,
				sizeof(*bh), GFP_KERNEL);
	if (bh == NULL)
		return -ENOMEM;
#endif

	if (length) {
		/*
		 * Datablock.
		 */
		bytes = -offset;
		compressed = SQUASHFS_COMPRESSED_BLOCK(length);
		length = SQUASHFS_COMPRESSED_SIZE_BLOCK(length);
		if (next_index)
			*next_index = index + length;

		TRACE("Block @ 0x%llx, %scompressed size %d, src size %d\n",
			index, compressed ? "" : "un", length, srclength);

		if (length < 0 || length > srclength ||
				(index + length) > msblk->bytes_used)
			goto read_failure;

#ifdef CONFIG_SQUASHFS_LINEAR
		if (LINEAR(msblk)) {
			c_buffer = squashfs_linear_read(sb, index, length);
			goto read_done;
		}
#endif
		for (b = 0; bytes < length; b++, cur_index++) {
			bh[b] = sb_getblk(sb, cur_index);
			if (bh[b] == NULL)
				goto block_release;
			bytes += msblk->devblksize;
		}
		ll_rw_block(READ, b, bh);
	} else {
		/*
		 * Metadata block.
		 */
		if ((index + 2) > msblk->bytes_used)
			goto read_failure;

#ifdef CONFIG_SQUASHFS_LINEAR
		if (LINEAR(msblk)) {
			if (!get_block_length_linear(sb, &cur_index, &offset,
						     &length))
				goto read_failure;
		} else {
			bh[0] = get_block_length(sb, &cur_index, &offset,
						 &length);
			if (bh[0] == NULL)
				goto read_failure;
			b = 1;
		}
#else
		bh[0] = get_block_length(sb, &cur_index, &offset, &length);
		if (bh[0] == NULL)
			goto read_failure;
		b = 1;
#endif

		bytes = msblk->devblksize - offset;
		compressed = SQUASHFS_COMPRESSED(length);
		length = SQUASHFS_COMPRESSED_SIZE(length);
		if (next_index)
			*next_index = index + length + 2;

		TRACE("Block @ 0x%llx, %scompressed size %d\n", index,
				compressed ? "" : "un", length);

		if (length < 0 || length > srclength ||
					(index + length) > msblk->bytes_used)
			goto block_release;
#ifdef CONFIG_SQUASHFS_LINEAR
		if (LINEAR(msblk)) {
			c_buffer = squashfs_linear_read(sb,
					cur_index * msblk->devblksize + offset,
					length);
			goto read_done;
		}
#endif

		for (; bytes < length; b++) {
			bh[b] = sb_getblk(sb, ++cur_index);
			if (bh[b] == NULL)
				goto block_release;
			bytes += msblk->devblksize;
		}
		ll_rw_block(READ, b - 1, bh + 1);
	}
#ifdef CONFIG_SQUASHFS_LINEAR
read_done:
#endif

	if (compressed) {
		int zlib_err = 0, zlib_init = 0;

		/*
		 * Uncompress block.
		 */

		mutex_lock(&msblk->read_data_mutex);

		msblk->stream.avail_out = 0;
		msblk->stream.avail_in = 0;

		bytes = length;
#ifdef CONFIG_SQUASHFS_LINEAR
		if (LINEAR(msblk)) {
			msblk->stream.next_in = c_buffer;
			msblk->stream.avail_in = bytes;
		}
#endif
		do {
			if (msblk->stream.avail_in == 0 && k < b) {
#ifdef CONFIG_SQUASHFS_LINEAR
				BUG_ON(LINEAR(msblk));
#endif
				avail = min(bytes, msblk->devblksize - offset);
				bytes -= avail;
				wait_on_buffer(bh[k]);
				if (!buffer_uptodate(bh[k]))
					goto release_mutex;

				if (avail == 0) {
					offset = 0;
					put_bh(bh[k++]);
					continue;
				}

				msblk->stream.next_in = bh[k]->b_data + offset;
				msblk->stream.avail_in = avail;
				offset = 0;
			}

			if (msblk->stream.avail_out == 0 && page < pages) {
				msblk->stream.next_out = buffer[page++];
				msblk->stream.avail_out = PAGE_CACHE_SIZE;
			}

			if (!zlib_init) {
				zlib_err = zlib_inflateInit(&msblk->stream);
				if (zlib_err != Z_OK) {
					ERROR("zlib_inflateInit returned"
						" unexpected result 0x%x,"
						" srclength %d\n", zlib_err,
						srclength);
					goto release_mutex;
				}
				zlib_init = 1;
			}

			zlib_err = zlib_inflate(&msblk->stream, Z_SYNC_FLUSH);

			if (msblk->stream.avail_in == 0 && k < b) {
#ifdef CONFIG_SQUASHFS_LINEAR
				BUG_ON(LINEAR(msblk));
#endif
				put_bh(bh[k++]);
			}
		} while (zlib_err == Z_OK);

		if (zlib_err != Z_STREAM_END) {
			ERROR("zlib_inflate error, data probably corrupt\n");
			goto release_mutex;
		}

		zlib_err = zlib_inflateEnd(&msblk->stream);
		if (zlib_err != Z_OK) {
			ERROR("zlib_inflate error, data probably corrupt\n");
			goto release_mutex;
		}
		length = msblk->stream.total_out;
		mutex_unlock(&msblk->read_data_mutex);
	} else {
		/*
		 * Block is uncompressed.
		 */
		int i, in, pg_offset = 0;

#ifdef CONFIG_SQUASHFS_LINEAR
		if (LINEAR(msblk)) {
			for (bytes = length; bytes; page++) {
				avail = min_t(int, bytes, PAGE_CACHE_SIZE);
				memcpy(buffer[page], c_buffer, avail);
				bytes -= avail;
				c_buffer += avail;
			}
			goto uncompress_done;
		}
#endif
		for (i = 0; i < b; i++) {
			wait_on_buffer(bh[i]);
			if (!buffer_uptodate(bh[i]))
				goto block_release;
		}

		for (bytes = length; k < b; k++) {
			in = min(bytes, msblk->devblksize - offset);
			bytes -= in;
			while (in) {
				if (pg_offset == PAGE_CACHE_SIZE) {
					page++;
					pg_offset = 0;
				}
				avail = min_t(int, in, PAGE_CACHE_SIZE -
						pg_offset);
				memcpy(buffer[page] + pg_offset,
						bh[k]->b_data + offset, avail);
				in -= avail;
				pg_offset += avail;
				offset += avail;
			}
			offset = 0;
			put_bh(bh[k]);
		}
	}
#ifdef CONFIG_SQUASHFS_LINEAR
uncompress_done:
#endif

	kfree(bh);
	return length;

release_mutex:
	mutex_unlock(&msblk->read_data_mutex);

block_release:
#ifdef CONFIG_SQUASHFS_LINEAR
	BUG_ON(LINEAR(msblk) && b != 0);
#endif
	for (; k < b; k++)
		put_bh(bh[k]);

read_failure:
	ERROR("squashfs_read_data failed to read block 0x%llx\n",
					(unsigned long long) index);
	kfree(bh);
	return -EIO;
}
