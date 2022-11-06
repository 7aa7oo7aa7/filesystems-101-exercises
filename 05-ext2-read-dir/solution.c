#include <solution.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ext2fs/ext2fs.h>

ssize_t read_block(int img, const uint32_t block, const size_t block_size, void* buf) {
    off_t offset = block_size * block;
    return pread(img, buf, block_size, offset);
}

struct ext2_dir_entry_2* get_dir_entry(void* buf, off_t offset) {
    return (struct ext2_dir_entry_2*) (buf + offset);
}

int report_direct(int img, const uint32_t block, const size_t block_size, ssize_t* left_to_read, void* buf) {
    ssize_t bytes_read = read_block(img, block, block_size, buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }

    ssize_t cur_left_to_read = block_size;
    if (*left_to_read < (ssize_t) block_size) {
        cur_left_to_read = *left_to_read;
    }

    char* file_name = (char*) calloc(EXT2_NAME_LEN + 1, sizeof(char));
    struct ext2_dir_entry_2* dir_entry = NULL;
    off_t offset = 0;
    for (dir_entry = get_dir_entry(buf, 0); dir_entry != NULL && dir_entry->inode != 0 && cur_left_to_read > 0; dir_entry = get_dir_entry(buf, offset)) {
        memcpy(file_name, dir_entry->name, dir_entry->name_len);
        file_name[dir_entry->name_len] = '\0';
        if (dir_entry->file_type == EXT2_FT_REG_FILE || dir_entry->file_type == EXT2_FT_DIR) {
            char file_type = (dir_entry->file_type == EXT2_FT_REG_FILE) ? 'f' : 'd';
            report_file(dir_entry->inode, file_type, file_name);
        }
        cur_left_to_read -= dir_entry->rec_len;
        offset += dir_entry->rec_len;
    }

    *left_to_read -= cur_left_to_read;
    free(file_name);
    return 0;
}

int report_indirect(int img, const uint32_t block, const size_t block_size, ssize_t* left_to_read, uint32_t* buf, int block_type) {
    ssize_t bytes_read = read_block(img, block, block_size, buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }
    void* indirect_block_buf = calloc(block_size, sizeof(char));
    int retval = 0;
    for (size_t i = 0; i < block_size / sizeof(uint32_t) && buf[i] != 0 && *left_to_read > 0; ++i) {
        if (block_type == EXT2_IND_BLOCK) {
            retval = report_direct(img, buf[i], block_size, left_to_read, indirect_block_buf);
        } else {
            retval = report_indirect(img, buf[i], block_size, left_to_read, (uint32_t*) indirect_block_buf, i - 1);
        }
        if (retval < 0) {
            break;
        }
    }
    free(indirect_block_buf);
    return retval;
}

int dump_dir(int img, int inode_nr) {
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

    // read all blocks
    ssize_t left_to_read = inode.i_size;
    void* buf = calloc(block_size, sizeof(char));
    int retval = 0;
    for (size_t i = 0; i < EXT2_N_BLOCKS && inode.i_block[i] != 0 && left_to_read > 0; ++i) {
        if (i < EXT2_NDIR_BLOCKS) {
            retval = report_direct(img, inode.i_block[i], block_size, &left_to_read, buf);
        } else if (i == EXT2_IND_BLOCK || i == EXT2_DIND_BLOCK || i == EXT2_TIND_BLOCK) {
            retval = report_indirect(img, inode.i_block[i], block_size, &left_to_read, (uint32_t*) buf, i);
        } else {
            retval = -1;
        }
        if (retval < 0) {
            break;
        }
    }

    free(buf);
    return retval;

    return 0;
}
