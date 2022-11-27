#include <solution.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "use: %s <ext2-image> <mount-point>\n", argv[0]);
		return 1;
	}

	int img = open(argv[1], O_RDONLY);
	if (img < 0)
		errx(1, "failed to open an ext2 image");

	int r = ext2fuse(img, argv[2]);

	close(img);
	return r;
}
