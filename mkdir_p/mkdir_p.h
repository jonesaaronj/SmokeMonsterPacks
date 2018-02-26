/** 
 * Copyright (c)
 * https://gist.github.com/JonathonReinhart/8c0d90191c38af2dcadb102c4e202950
 */

#ifndef MKDIR_H
#define MKDIR_H

#include <string.h>
#include <limits.h>     /* PATH_MAX */
#include <sys/stat.h>   /* mkdir(2) */
#include <errno.h>

int mkdir_p(const char *path);

#endif
