#include <solution.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <ext2fs/ext2fs.h>

ssize_t read_block(int img, const uint32_t block, const size_t block_size, void* buf) {
    off_t offset = block_size * block;
    return pread(img, buf, block_size, offset);
}

int copy_direct(int img, int out, const uint32_t block, const size_t block_size, ssize_t* left_to_copy, void* buf) {
    ssize_t bytes_read = read_block(img, block, block_size, buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }
    size_t bytes_to_write = block_size;
    if (*left_to_copy < (ssize_t) block_size) {
        bytes_to_write = (size_t) (*left_to_copy);
    }
    ssize_t bytes_written = pwrite(out, buf, bytes_to_write, 0);
    if (bytes_written < (ssize_t) bytes_to_write) {
        return -errno;
    }
    *left_to_copy -= bytes_to_write;
    return 0;
}

int copy_indirect(int img, int out, const uint32_t block, const size_t block_size, ssize_t* left_to_copy, void* buf, bool is_double) {
    ssize_t bytes_read = read_block(img, block, block_size, buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }
    uint32_t* indirect_block_buf = (uint32_t*) calloc(block_size / 4, sizeof(uint32_t));
    int retval = 0;
    for (size_t i = 0; i < block_size / 4 && indirect_block_buf[i] != 0 && *left_to_copy > 0; ++i) {
        if (is_double) {
            retval = copy_indirect(img, out, indirect_block_buf[i], block_size, left_to_copy, (void*) indirect_block_buf, false);
        } else {
            retval = copy_direct(img, out, indirect_block_buf[i], block_size, left_to_copy, (void*) indirect_block_buf);
        }
        if (retval < 0) {
            break;
        }
    }
    free(indirect_block_buf);
    return retval;
}

int dump_file(int img, int inode_nr, int out) {
    // read superblock
    size_t super_block_size = sizeof(struct ext2_super_block);
    struct ext2_super_block super_block;
    ssize_t bytes_read = pread(img, (void*) &super_block, super_block_size, SUPERBLOCK_OFFSET);
    if (bytes_read < (ssize_t) super_block_size) {
        return -errno;
    }

    size_t block_size = 1024 << super_block.s_log_block_size;

    // read block group
    size_t block_group_size = sizeof(struct ext2_group_desc);
    int inode_block_group = (inode_nr - 1) / super_block.s_inodes_per_group;
    off_t block_group_offset = block_size * (super_block.s_first_data_block + 1) + block_group_size * inode_block_group;
    struct ext2_group_desc block_group;
    bytes_read = pread(img, (void*) &block_group, block_group_size, block_group_offset);
    if (bytes_read < (ssize_t) block_group_size) {
        return -errno;
    }

    // read inode
    int inode_block = (inode_nr - 1) % super_block.s_inodes_per_group;
    off_t inode_offset = block_size * block_group.bg_inode_table + super_block.s_inode_size * inode_block;
    size_t inode_size = sizeof(struct ext2_inode);
    struct ext2_inode inode;
    bytes_read = pread(img, (void*) &inode, inode_size, inode_offset);
    if (bytes_read < (ssize_t) inode_size) {
        return -errno;
    }

    // copy all blocks
    ssize_t left_to_copy = inode.i_size;
    void* buf = calloc(block_size, sizeof(char));
    int retval = 0;
    for (size_t i = 0; i < EXT2_N_BLOCKS && inode.i_block[i] != 0 && left_to_copy > 0; ++i) {
        if (i < EXT2_NDIR_BLOCKS) {
            retval = copy_direct(img, out, inode.i_block[i], block_size, &left_to_copy, buf);
        } else if (i == EXT2_IND_BLOCK) {
            retval = copy_indirect(img, out, inode.i_block[i], block_size, &left_to_copy, buf, false);
        } else if (i == EXT2_DIND_BLOCK) {
            retval = copy_indirect(img, out, inode.i_block[i], block_size, &left_to_copy, buf, true);
        } else {
            retval = -1;
        }
        if (retval < 0) {
            break;
        }
    }

    free(buf);
    return retval;
}
