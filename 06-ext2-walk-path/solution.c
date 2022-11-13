#include <solution.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ext2fs/ext2fs.h>

ssize_t read_block(int img, const uint32_t block, const size_t block_size, void* buf) {
    off_t offset = block_size * block;
    return pread(img, buf, block_size, offset);
}

ssize_t read_super_block(int img, struct ext2_super_block* super_block) {
    size_t super_block_size = sizeof(struct ext2_super_block);
    ssize_t bytes_read = pread(img, super_block, super_block_size, SUPERBLOCK_OFFSET);
    if (bytes_read < (ssize_t) super_block_size) {
        return -errno;
    }
    return bytes_read;
}

ssize_t read_block_group(int img, int inode_nr, struct ext2_super_block* super_block, struct ext2_group_desc* block_group) {
    size_t block_size = 1024 << super_block->s_log_block_size;
    size_t block_group_size = sizeof(struct ext2_group_desc);
    int inode_block_group = (inode_nr - 1) / super_block->s_inodes_per_group;
    off_t block_group_offset = block_size * (super_block->s_first_data_block + 1) + block_group_size * inode_block_group;
    ssize_t bytes_read = pread(img, block_group, block_group_size, block_group_offset);
    if (bytes_read < (ssize_t) block_group_size) {
        return -errno;
    }
    return bytes_read;
}

ssize_t read_inode(int img, int inode_nr, struct ext2_super_block* super_block, struct ext2_group_desc* block_group, struct ext2_inode* inode) {
    size_t block_size = 1024 << super_block->s_log_block_size;
    int inode_block = (inode_nr - 1) % super_block->s_inodes_per_group;
    off_t inode_offset = block_size * block_group->bg_inode_table + super_block->s_inode_size * inode_block;
    size_t inode_size = sizeof(struct ext2_inode);
    ssize_t bytes_read = pread(img, inode, inode_size, inode_offset);
    if (bytes_read < (ssize_t) inode_size) {
        return -errno;
    }
    return bytes_read;
}

int get_inode_direct(int img, uint32_t block, size_t block_size, void* buf, const char* filename, size_t filename_len) {
    ssize_t bytes_read = read_block(img, block, block_size, buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }
    struct ext2_dir_entry_2* dirent = (struct ext2_dir_entry_2*) buf;
    for (size_t offset = 0; offset < block_size && dirent->inode != 0; offset += dirent->rec_len) {
        dirent = (struct ext2_dir_entry_2*) (buf + offset);
        if (filename_len == dirent->name_len && strncmp(filename, dirent->name, filename_len) == 0) {
            return dirent->inode;
        }
    }
    return 0;
}

int get_inode_indirect(int img, uint32_t block, size_t block_size, uint32_t* buf, const char* filename, size_t filename_len, bool is_double) {
    ssize_t bytes_read = read_block(img, block, block_size, (void*) buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }
    void* indirect_block_buf = calloc(block_size, sizeof(char));
    int retval = 0;
    for (size_t i = 0; retval == 0 && i < block_size / sizeof(uint32_t) && buf[i] != 0; ++i) {
        if (is_double) {
            retval = get_inode_indirect(img, buf[i], block_size, (uint32_t*) indirect_block_buf, filename, filename_len, false);
        } else {
            retval = get_inode_direct(img, buf[i], block_size, indirect_block_buf, filename, filename_len);
        }
    }
    free(indirect_block_buf);
    return retval;
}

int get_next_inode(int img, size_t block_size, struct ext2_inode* inode, const char* filename, size_t filename_len) {
    void* buf = calloc(block_size, sizeof(char));
    int retval = 0;
    for (size_t i = 0; retval == 0 && i < EXT2_N_BLOCKS && inode->i_block[i] != 0; ++i) {
        if (i < EXT2_NDIR_BLOCKS) {
            retval = get_inode_direct(img, inode->i_block[i], block_size, buf, filename, filename_len);
        } else if (i == EXT2_IND_BLOCK) {
            retval = get_inode_indirect(img, inode->i_block[i], block_size, (uint32_t*) buf, filename, filename_len, false);
        } else if (i == EXT2_DIND_BLOCK) {
            retval = get_inode_indirect(img, inode->i_block[i], block_size, (uint32_t*) buf, filename, filename_len, true);
        } else {
            retval = -ENOENT;
        }
    }
    free(buf);
    return retval;
}

int get_inode(int img, const char* path, struct ext2_super_block* super_block) {
    size_t block_size = 1024 << super_block->s_log_block_size;
    int inode_nr = 2;
    while (path != NULL && *path != '\0') {
        ++path;

        struct ext2_group_desc block_group;
        ssize_t bytes_read = read_block_group(img, inode_nr, super_block, &block_group);
        if (bytes_read < 0) {
            return bytes_read;
        }

        struct ext2_inode inode;
        bytes_read = read_inode(img, inode_nr, super_block, &block_group, &inode);
        if (bytes_read < 0) {
            return bytes_read;
        }

        if ((inode.i_mode & LINUX_S_IFDIR) == 0) {
            return -ENOTDIR;
        }

        char filename[EXT2_NAME_LEN + 1];
        size_t filename_len = 0;
        for (; path != NULL && *path != '\0' && *path != '/'; ++path) {
            filename[filename_len++] = *path;
        }
        filename[filename_len] = '\0';

        inode_nr = get_next_inode(img, block_size, &inode, filename, filename_len);
        if (inode_nr < 0) {
            return inode_nr;
        } else if (inode_nr == 0) {
            return -ENOENT;
        }
    }
    return inode_nr;
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
    ssize_t bytes_written = write(out, buf, bytes_to_write);
    if (bytes_written < (ssize_t) bytes_to_write) {
        return -errno;
    }
    *left_to_copy -= bytes_to_write;
    return 0;
}

int copy_indirect(int img, int out, const uint32_t block, const size_t block_size, ssize_t* left_to_copy, uint32_t* buf, bool is_double) {
    ssize_t bytes_read = read_block(img, block, block_size, buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }
    void* indirect_block_buf = calloc(block_size, sizeof(char));
    int retval = 0;
    for (size_t i = 0; retval >= 0 && i < block_size / sizeof(uint32_t) && buf[i] != 0 && *left_to_copy > 0; ++i) {
        if (is_double) {
            retval = copy_indirect(img, out, buf[i], block_size, left_to_copy, (uint32_t*) indirect_block_buf, false);
        } else {
            retval = copy_direct(img, out, buf[i], block_size, left_to_copy, (void*) indirect_block_buf);
        }
    }
    free(indirect_block_buf);
    return retval;
}

int copy_file(int img, int out, struct ext2_super_block* super_block, struct ext2_inode* inode) {
    size_t block_size = 1024 << super_block->s_log_block_size;
    ssize_t left_to_copy = inode->i_size;
    void* buf = calloc(block_size, sizeof(char));
    int retval = 0;
    for (size_t i = 0; retval >= 0 && i < EXT2_N_BLOCKS && inode->i_block[i] != 0 && left_to_copy > 0; ++i) {
        if (i < EXT2_NDIR_BLOCKS) {
            retval = copy_direct(img, out, inode->i_block[i], block_size, &left_to_copy, buf);
        } else if (i == EXT2_IND_BLOCK) {
            retval = copy_indirect(img, out, inode->i_block[i], block_size, &left_to_copy, (uint32_t*) buf, false);
        } else if (i == EXT2_DIND_BLOCK) {
            retval = copy_indirect(img, out, inode->i_block[i], block_size, &left_to_copy, (uint32_t*) buf, true);
        } else {
            retval = -1;
        }
    }
    free(buf);
    return retval;
}

int dump_file(int img, const char* path, int out) {
    // read super_block
    struct ext2_super_block super_block;
    ssize_t bytes_read = read_super_block(img, &super_block);
    if (bytes_read < 0) {
        return -errno;
    }

    // find inode
    int inode_nr = get_inode(img, path, &super_block);
    if (inode_nr < 0) {
        return inode_nr;
    }

    // read block group
    struct ext2_group_desc block_group;
    bytes_read = read_block_group(img, inode_nr, &super_block, &block_group);
    if (bytes_read < 0) {
        return bytes_read;
    }

    // read inode
    struct ext2_inode inode;
    bytes_read = read_inode(img, inode_nr, &super_block, &block_group, &inode);
    if (bytes_read < 0) {
        return bytes_read;
    }

    // copy all blocks
    int retval = copy_file(img, out, &super_block, &inode);
    if (retval < 0) {
        return retval;
    }

    return 0;
}
