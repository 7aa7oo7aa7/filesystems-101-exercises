#pragma once

#include <unistd.h>

/**
   Implement this function to mount an ext2 file system image @img
   via FUSE to @mntp.

   Any attempt write to the FS must report EROFS.
*/
int ext2fuse(int img, const char *mntp);
