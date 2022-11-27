#include <solution.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ext2fs/ext2fs.h>
#include <fuse.h>

int ext2fuse_img;

bool is_writable(struct fuse_file_info* ffi) {
    return (ffi->flags & O_ACCMODE) != O_RDONLY;
}

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
            if (dirent->file_type != EXT2_FT_DIR) {
                return -ENOTDIR;
            }
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
    for (size_t i = 0; retval == 0 && i < EXT2_N_BLOCKS; ++i) {
        if (inode->i_block[i] == 0) {
            assert(0);
            break;
        }
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
    assert(inode_nr >= 0);
    return inode_nr;
}

int copy_direct(int img, const uint32_t block, const size_t block_size, ssize_t* left_to_copy, void* buf, off_t* offset) {
    ssize_t bytes_read = read_block(img, block, block_size, buf + *offset);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }
    size_t bytes_to_write = block_size;
    if (*left_to_copy < (ssize_t) block_size) {
        bytes_to_write = (size_t) (*left_to_copy);
    }
    *left_to_copy -= bytes_to_write;
    *offset += bytes_to_write;
    return 0;
}

int copy_indirect(int img, const uint32_t block, const size_t block_size, ssize_t* left_to_copy, void* file_buf, off_t* offset, size_t block_type) {
    uint32_t* indirect_block_buf = calloc(block_size, sizeof(char));
    ssize_t bytes_read = read_block(img, block, block_size, indirect_block_buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }
    int retval = 0;
    for (size_t i = 0; retval >= 0 && i < block_size / sizeof(uint32_t) && *left_to_copy > 0 && indirect_block_buf[i] != 0; ++i) {
        if (block_type == EXT2_IND_BLOCK) {
            retval = copy_direct(img, indirect_block_buf[i], block_size, left_to_copy, file_buf, offset);
        } else {
            retval = copy_indirect(img, indirect_block_buf[i], block_size, left_to_copy, file_buf, offset, block_type - 1);
        }
    }
    free(indirect_block_buf);
    return retval;
}

int copy_file(int img, struct ext2_super_block* super_block, struct ext2_inode* inode, size_t* file_size, char* file_buf) {
    size_t block_size = 1024 << super_block->s_log_block_size;
    ssize_t left_to_copy = inode->i_size;
    *file_size = inode->i_size;
    off_t offset = 0;
    file_buf = calloc(left_to_copy, sizeof(char));
    int retval = 0;
    for (size_t i = 0; retval >= 0 && i < EXT2_N_BLOCKS && left_to_copy > 0 && inode->i_block[i] != 0; ++i) {
        if (i < EXT2_NDIR_BLOCKS) {
            retval = copy_direct(img, inode->i_block[i], block_size, &left_to_copy, file_buf, &offset);
        } else if (i == EXT2_IND_BLOCK || i == EXT2_DIND_BLOCK) {
            retval = copy_indirect(img, inode->i_block[i], block_size, &left_to_copy, file_buf, &offset, i);
        }
    }
    return retval;
}

int dump_file(int img, int inode_nr, size_t* file_size, char* file_buf) {
    // read super_block
    struct ext2_super_block super_block;
    ssize_t bytes_read = read_super_block(img, &super_block);
    if (bytes_read < 0) {
        return -errno;
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
    int retval = copy_file(img, &super_block, &inode, file_size, file_buf);
    if (retval < 0) {
        return retval;
    }

    return 0;
}

struct ext2_dir_entry_2* get_dir_entry(void* buf, const size_t block_size, off_t offset) {
    if (offset >= (off_t) block_size) {
        return NULL;
    }
    return (struct ext2_dir_entry_2*) (buf + offset);
}

int copy_dir_direct(int img, const uint32_t block, const size_t block_size, ssize_t* left_to_read, void* buf, void* dir_buf, fuse_fill_dir_t filler) {
    ssize_t bytes_read = read_block(img, block, block_size, buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }

    ssize_t cur_left_to_read = block_size;
    if (*left_to_read < (ssize_t) block_size) {
        cur_left_to_read = *left_to_read;
    }
    *left_to_read -= cur_left_to_read;

    char* file_name = (char*) calloc(EXT2_NAME_LEN + 1, sizeof(char));
    struct ext2_dir_entry_2* dir_entry = get_dir_entry(buf, block_size, 0);
    off_t offset = 0;
    for (; dir_entry != NULL && dir_entry->inode != 0 && cur_left_to_read > 0; dir_entry = get_dir_entry(buf, block_size, offset)) {
        memcpy(file_name, dir_entry->name, dir_entry->name_len);
        file_name[dir_entry->name_len] = '\0';
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = dir_entry->inode;
        if (dir_entry->file_type == EXT2_FT_DIR) {
			st.st_mode = S_IFDIR | S_IRUSR | S_IRGRP | S_IROTH;
		} else {
			st.st_mode = S_IFREG | S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
		}
        filler(dir_buf, file_name, &st, 0, 0);
        cur_left_to_read -= dir_entry->rec_len;
        offset += dir_entry->rec_len;
    }

    free(file_name);
    return 0;
}

int copy_dir_indirect(int img, const uint32_t block, const size_t block_size, ssize_t* left_to_read, uint32_t* buf, void* dir_buf, fuse_fill_dir_t filler, int block_type) {
    ssize_t bytes_read = read_block(img, block, block_size, buf);
    if (bytes_read < (ssize_t) block_size) {
        return -errno;
    }
    void* indirect_block_buf = calloc(block_size, sizeof(char));
    int retval = 0;
    for (size_t i = 0; retval >= 0 && i < block_size / sizeof(uint32_t) && *left_to_read > 0 && buf[i] != 0; ++i) {
        if (block_type == EXT2_IND_BLOCK) {
            retval = copy_dir_direct(img, buf[i], block_size, left_to_read, indirect_block_buf, dir_buf, filler);
        } else {
            retval = copy_dir_indirect(img, buf[i], block_size, left_to_read, (uint32_t*) indirect_block_buf, dir_buf, filler, i - 1);
        }
    }
    free(indirect_block_buf);
    return retval;
}

int copy_dir(int img, struct ext2_super_block* super_block, struct ext2_inode* inode, void* dir_buf, fuse_fill_dir_t filler) {
    size_t block_size = 1024 << super_block->s_log_block_size;
    ssize_t left_to_copy = inode->i_size;
    void* buf = calloc(block_size, sizeof(char));
    int retval = 0;
    for (size_t i = 0; retval >= 0 && i < EXT2_N_BLOCKS && left_to_copy > 0 && inode->i_block[i] != 0; ++i) {
        if (i < EXT2_NDIR_BLOCKS) {
            retval = copy_dir_direct(img, inode->i_block[i], block_size, &left_to_copy, buf, dir_buf, filler);
        } else if (i == EXT2_IND_BLOCK || i == EXT2_DIND_BLOCK) {
            retval = copy_dir_indirect(img, inode->i_block[i], block_size, &left_to_copy, (uint32_t*) buf, dir_buf, filler, i);
        }
    }
    free(buf);
    return retval;
}

int dump_dir(int img, int inode_nr, void* dir_buf, fuse_fill_dir_t filler) {
    // read super_block
    struct ext2_super_block super_block;
    ssize_t bytes_read = read_super_block(img, &super_block);
    if (bytes_read < 0) {
        return -errno;
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
    int retval = copy_dir(img, &super_block, &inode, dir_buf, filler);
    if (retval < 0) {
        return retval;
    }

    return 0;
}

static int ext2fuse_write(const char* path, const char* buf, size_t size, off_t off, struct fuse_file_info* ffi) {
    (void) path;
    (void) buf;
    (void) size;
    (void) off;
    (void) ffi;
    return -EROFS;
}

static int ext2fuse_create(const char* path, mode_t mode, struct fuse_file_info* ffi) {
    (void) path;
    (void) mode;
    (void) ffi;
    return -EROFS;
}

static int ext2fuse_write_buf(const char* path, struct fuse_bufvec* buf, off_t offset, struct fuse_file_info* ffi) {
    (void) path;
    (void) buf;
    (void) offset;
    (void) ffi;
    return -EROFS;
}

static int ext2fuse_mkdir(const char* path, mode_t mode) {
    (void) path;
    (void) mode;
    return -EROFS;
}

static int ext2fuse_mknod(const char* path, mode_t mode, dev_t rdev) {
    (void) path;
    (void) mode;
    (void) rdev;
    return -EROFS;
}

static int ext2fuse_getattr(const char* path, struct stat* stat, struct fuse_file_info* ffi) {
    (void) ffi;
    memset(stat, 0, sizeof(struct stat));
    struct ext2_super_block super_block;
    ssize_t bytes_read = read_super_block(ext2fuse_img, &super_block);
    if (bytes_read < 0) {
        return -errno;
    }
    int inode_nr = get_inode(ext2fuse_img, path, &super_block);
    if (inode_nr < 0) {
        return -ENOENT;
    }
    struct ext2_group_desc block_group;
    bytes_read = read_block_group(ext2fuse_img, inode_nr, &super_block, &block_group);
    if (bytes_read < 0) {
        return bytes_read;
    }
    struct ext2_inode inode;
    bytes_read = read_inode(ext2fuse_img, inode_nr, &super_block, &block_group, &inode);
    if (bytes_read < 0) {
        return bytes_read;
    }
    stat->st_ino = inode_nr;
    stat->st_mode = inode.i_mode;
    stat->st_nlink = inode.i_links_count;
    stat->st_uid = inode.i_uid;
    stat->st_gid = inode.i_gid;
    stat->st_size = inode.i_size;
    stat->st_blksize = (1024 << super_block.s_log_block_size);
    stat->st_blocks = inode.i_blocks;
    stat->st_atime = inode.i_atime;
    stat->st_mtime = inode.i_mtime;
    stat->st_ctime = inode.i_ctime;
    return 0;
}

static int ext2fuse_opendir(const char* path, struct fuse_file_info* ffi) {
    if (is_writable(ffi)) {
        return -EROFS;
    } else if (path[0] != '/') {
        ffi->fh = 2;
        return 0;
    }
    struct ext2_super_block super_block;
    ssize_t bytes_read = read_super_block(ext2fuse_img, &super_block);
    if (bytes_read < 0) {
        return -errno;
    }
    int inode_nr = get_inode(ext2fuse_img, path, &super_block);
    if (inode_nr < 0) {
        return -ENOENT;
    }
    ffi->fh = inode_nr;
    struct ext2_group_desc block_group;
    bytes_read = read_block_group(ext2fuse_img, inode_nr, &super_block, &block_group);
    if (bytes_read < 0) {
        return bytes_read;
    }
    struct ext2_inode inode;
    bytes_read = read_inode(ext2fuse_img, inode_nr, &super_block, &block_group, &inode);
    if (bytes_read < 0) {
        return bytes_read;
    }
    if (!S_ISDIR(inode.i_mode)) {
        return -ENOTDIR;
    }
    return 0;
}

static int ext2fuse_readdir(const char* path, void* dir_buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* ffi, enum fuse_readdir_flags frf) {
    (void) path;
    (void) offset;
    (void) frf;
    return dump_dir(ext2fuse_img, ffi->fh, dir_buf, filler);
}

static int ext2fuse_open(const char* path, struct fuse_file_info* ffi) {
    if (is_writable(ffi)) {
        return -EROFS;
    }
    struct ext2_super_block super_block;
    ssize_t bytes_read = read_super_block(ext2fuse_img, &super_block);
    if (bytes_read < 0) {
        return -errno;
    }
    int inode_nr = get_inode(ext2fuse_img, path, &super_block);
    if (inode_nr < 0) {
        return -ENOENT;
    }
    ffi->fh = inode_nr;
    return 0;
}

static int ext2fuse_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* ffi) {
    (void) path;
    size_t file_size = 0;
    char* file_buf = NULL;
    int retval = dump_file(ext2fuse_img, ffi->fh, &file_size, file_buf);
    if (retval < 0) {
        return retval;
    }
    if (offset < (off_t) file_size) {
		if (size + offset > file_size) {
			size = file_size - offset;
		}
		memcpy(buf, file_buf + offset, size);
	} else {
		size = 0;
	}
	free(file_buf);
	return size;
}

static const struct fuse_operations ext2_ops = {
    .write = ext2fuse_write,
    .create = ext2fuse_create,
    .write_buf = ext2fuse_write_buf,
    .mkdir = ext2fuse_mkdir,
    .mknod = ext2fuse_mknod,
    .getattr = ext2fuse_getattr,
    .opendir = ext2fuse_opendir,
    .readdir = ext2fuse_readdir,
    .open = ext2fuse_open,
    .read = ext2fuse_read,
};

int ext2fuse(int img, const char *mntp) {
    ext2fuse_img = img;

    char *argv[] = {"exercise", "-f", (char*) mntp, NULL};
    return fuse_main(3, argv, &ext2_ops, NULL);
}
