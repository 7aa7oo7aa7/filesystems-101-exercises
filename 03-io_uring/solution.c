#include <solution.h>

#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "liburing.h"

const size_t NUM_WORKERS = 4;
const size_t IO_BLOCK_SIZE = (256 << 10);

struct user_data {
    int is_write;
    off_t first_offset;
    off_t offset;
    size_t buf_size;
    void* buf;
};

struct read_info {
    size_t size;
    off_t offset;
};

struct read_info get_read_info(size_t* bytes_to_read, off_t* read_offset) {
    struct read_info info;
    info.size = *bytes_to_read;
    info.offset = *read_offset;
    if (info.size > IO_BLOCK_SIZE) {
        info.size = IO_BLOCK_SIZE;
    }
    *bytes_to_read -= info.size;
    *read_offset += info.size;
    return info;
}

int read_request(struct io_uring* ring, off_t offset, size_t bytes_to_read, int in) {
    // create data
    struct user_data* data = calloc(sizeof(struct user_data), 1);
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    if (sqe == NULL) {
        return 1;
    }
    data->is_write = 0;
    data->first_offset = offset;
    data->offset = 0;
    data->buf_size = bytes_to_read;
    data->buf = calloc(bytes_to_read, sizeof(char));
    if (data->buf == NULL) {
        return 2;
    }

    // prepare read
    io_uring_prep_read(sqe, in, data->buf, data->buf_size, data->offset);
    io_uring_sqe_set_data(sqe, (void*) &data);
    io_uring_submit(ring);

    return 0;
}

int write_request(struct io_uring* ring, struct user_data* data, int out) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
	io_uring_prep_write(sqe, out, data->buf, data->buf_size, data->first_offset);
    io_uring_sqe_set_data(sqe, (void*) data);
	io_uring_submit(ring);
    return 0;
}

int requeue(struct io_uring* ring, struct user_data* data, off_t offset, int in, int out) {
    // modify offset
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    data->offset += offset;
    off_t total_offset = data->offset + data->first_offset;

    // reschedule read or write
	if (data->is_write == 0) {
		io_uring_prep_read(sqe, in, data->buf, data->buf_size, total_offset);
	} else {
		io_uring_prep_write(sqe, out, data->buf, data->buf_size, total_offset);
    }
	io_uring_sqe_set_data(sqe, (void*) data);
    io_uring_submit(ring);

    return 0;
}

int copy(int in, int out) {
    int errno_or_zero = 0;

    struct io_uring ring;
    errno_or_zero = io_uring_queue_init(NUM_WORKERS, &ring, 0);
    if (errno_or_zero < 0) {
        return errno_or_zero;
    }

    struct stat in_stat;
    if (fstat(in, &in_stat) == -1) {
        return -errno;
    }

    off_t read_offset = 0;
    struct io_uring_cqe* cqe;

    size_t bytes_to_read = (size_t) in_stat.st_size;
    size_t bytes_to_write = bytes_to_read;

    size_t num_read_workers = 0;
    size_t num_write_workers = 0;
    while (bytes_to_read > 0 || bytes_to_write > 0) {

        // read loop
        for (; bytes_to_read > 0 && num_read_workers + num_write_workers < NUM_WORKERS; ++num_read_workers) {
            struct read_info info = get_read_info(&bytes_to_read, &read_offset);
            if (info.size == 0) {
                break;
            }
            errno_or_zero = read_request(&ring, info.offset, info.size, in);
            if (errno_or_zero < 0) {
                return errno_or_zero;
            }
            errno_or_zero = io_uring_submit(&ring);
            if (errno_or_zero < 0) {
                return errno_or_zero;
            }
        }

        size_t should_wait_cqe = 1;
        while (bytes_to_write > 0) {

            // get cqe
            if (should_wait_cqe == 0) {
                errno_or_zero = io_uring_peek_cqe(&ring, &cqe);
                if (errno_or_zero == -EAGAIN) {
                    cqe = NULL;
                } else if (errno_or_zero < 0) {
                    return errno_or_zero;
                }
            } else {
                should_wait_cqe = 0;
                errno_or_zero = io_uring_wait_cqe(&ring, &cqe);
                if (errno_or_zero != 0) {
                    return errno_or_zero;
                }
            }
            if (cqe == NULL) {
                break;
            }

            // requeue if necessary
            struct user_data* data = io_uring_cqe_get_data(cqe);
            if (cqe->res == -EAGAIN) {
                errno_or_zero = requeue(&ring, data, 0, in, out);
                if (errno_or_zero != 0) {
                    return errno_or_zero;
                }
                io_uring_cqe_seen(&ring, cqe);
                continue;
            }
            if (cqe->res < 0) {
                return cqe->res;
            }

            if ((size_t) cqe->res == data->buf_size) {
                // write or free a worker
                if (data->is_write == 0) {
                    data->is_write = 1;
	                data->offset = 0;
                    errno_or_zero = write_request(&ring, data, out);
                    if (errno_or_zero != 0) {
                        return errno_or_zero;
                    }
                    bytes_to_write -= data->buf_size;
                    ++num_write_workers;
                } else {
                    free(data);
                    --num_write_workers;
                }
            } else {
                // requeue if read too little
                errno_or_zero = requeue(&ring, data, cqe->res, in, out);
                if (errno_or_zero != 0) {
                    return errno_or_zero;
                }
            }
            io_uring_cqe_seen(&ring, cqe);
        }

    }

    // wait for remaining writers
    for (; num_write_workers > 0; --num_write_workers) {
        errno_or_zero = io_uring_wait_cqe(&ring, &cqe);
        if (errno_or_zero != 0) {
            return errno_or_zero;
        }
        errno_or_zero = cqe->res;
        if (errno_or_zero < 0) {
            return errno_or_zero;
        }
        free(io_uring_cqe_get_data(cqe));
        io_uring_cqe_seen(&ring, cqe);
    }

    io_uring_queue_exit(&ring);
    free(cqe);
    return 0;
}
