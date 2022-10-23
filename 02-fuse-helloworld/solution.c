#include <solution.h>

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/stat.h>

const size_t MAX_PID_LENGTH = 5;  // max pid is 32768

static bool is_root_dir(const char* path) {
	return strcmp(path, "/") == 0;
}

static bool is_hello_file(const char* path) {
	return strcmp(path + 1, "hello") == 0;
}

static size_t get_hello_file_content_maxlen() {
	return strlen("hello, \n") + MAX_PID_LENGTH;
}

static void get_hello_file_content(char* buf) {
	// buf length must be >= get_hello_file_content_maxlen()
	pid_t pid = fuse_get_context()->pid;
	sprintf(buf, "hello, %d\n", pid);
}

static int hellofs_getattr(const char* path, 
	struct stat* st, struct fuse_file_info* fi) {
	(void) fi;

	memset(st, 0, sizeof(struct stat));

	if (is_root_dir(path)) {
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2;
	} else if (is_hello_file(path)) {
		char hello_file_content[get_hello_file_content_maxlen()];
		get_hello_file_content(hello_file_content);
		size_t length = strlen(hello_file_content);

		st->st_mode = S_IFREG | 0444;
		st->st_nlink = 1;
		st->st_size = (off_t) length;
	} else {
		return -ENOENT;
	}

	return 0;
}

static int hellofs_open(const char* path, struct fuse_file_info* fi) {
	if (!is_hello_file(path)) {
		return -ENOENT;
	} else if ((fi->flags & O_ACCMODE) != O_RDONLY) {
		return -EACCES;
	}
	
	return 0;
}

static int hellofs_read(const char* path, char* buf, 
	size_t size, off_t offset, struct fuse_file_info* fi) {
	(void) fi;

	if (!is_hello_file(path)) {
		return -ENOENT;
	}

	char hello_file_content[get_hello_file_content_maxlen()];
	get_hello_file_content(hello_file_content);
	size_t length = strlen(hello_file_content);

	if (offset < (off_t) length) {
		if (size + (size_t) offset > length) {
			size = length - (size_t) offset;
		}
		memcpy(buf, hello_file_content + offset, size);
	} else {
		size = 0;
	}

	return size;
}

static int hellofs_readdir(const char* path, void* buf, 
	fuse_fill_dir_t filler, off_t offset, 
	struct fuse_file_info* fi, enum fuse_readdir_flags flags) {
	(void) flags;
	(void) fi;
	(void) offset;

	if (!is_root_dir(path)) {
		return -ENOENT;
	}

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	filler(buf, "hello", NULL, 0, 0);

	return 0;
}

static int hellofs_write(const char* path, const char* buf, 
	size_t size, off_t offset, struct fuse_file_info* fi) {
	(void) path;
	(void) buf;
	(void) size;
	(void) offset;
	(void) fi;

	// no write to the FS
	return -EROFS;
}

static int hellofs_mkdir(const char* path, mode_t mode) {
	(void) path;
	(void) mode;

	// no write to the FS
	return -EROFS;
}

static int hellofs_mknod(const char* path, mode_t mode, dev_t dev) {
	(void) path;
	(void) mode;
	(void) dev;

	// no write to the FS
	return -EROFS;
}

static int hellofs_write_buf(const char* path, struct fuse_bufvec* buf, off_t offset, struct fuse_file_info* fi) {
	(void) path;
	(void) buf;
	(void) offset;
	(void) fi;

	// no write to the FS
	return -EROFS;
}

static int hellofs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	(void) path;
	(void) mode;
	(void) fi;

	// no write to the FS
	return -EROFS;
}

static int hellofs_truncate(const char* path, off_t offset, struct fuse_file_info* fi) {
	(void) path;
	(void) offset;
	(void) fi;

	// no write to the FS
	return -EROFS;
}

static int hellofs_symlink(const char* path, const char* link) {
	(void) path;
	(void) link;

	// no write to the FS
	return -EROFS;
}

static const struct fuse_operations hellofs_ops = {
	.getattr = hellofs_getattr,
	.open = hellofs_open,
	.read = hellofs_read,
	.readdir = hellofs_readdir,
	.write = hellofs_write,
	.mkdir = hellofs_mkdir,
	.mknod = hellofs_mknod,
	.write_buf = hellofs_write_buf,
	.create = hellofs_create,
	.truncate = hellofs_truncate,
	.symlink = hellofs_symlink
};

int helloworld(const char *mntp) {
	char *argv[] = {"exercise", "-f", (char *)mntp, NULL};
	return fuse_main(3, argv, &hellofs_ops, NULL);
}
