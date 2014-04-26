/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR 

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>

       //realpath
#include <limits.h>
#include <stdlib.h>

#include "aes-crypt.h"

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif



#define XMP_DATA ((xmp_state *) fuse_get_context()->private_data)
#define TMP_SUFFIX ".tmp"
#define XATTR_NAME "user.pa4-encfs.encrypted"

typedef struct {
	char* rootdir;
	char* key;
} xmp_state;

static void *xmp_init(struct fuse_conn_info *conn){
	(void)conn; //hates warnings precious
    return XMP_DATA;
}

static void xmp_destroy(void *userdata){
	(void)userdata;
	free(XMP_DATA->rootdir);
	free(XMP_DATA->key);
}

// return full path, instead of relative path- stop mirroring / 
static char* xmp_fullpath(const char *path)
{
	char* fullpath;
	int pathlen;

	pathlen = strlen(path) + strlen(XMP_DATA->rootdir) + 1;

	fullpath = malloc(pathlen*sizeof(char));

    strcpy(fullpath, XMP_DATA->rootdir);
    strcat(fullpath, path); 

    return fullpath;
}

static char* xmp_temppath(const char* path)
{
	char* temppath;
	int pathlen;

	pathlen = strlen(path) + strlen(TMP_SUFFIX) +1;

	temppath = malloc(pathlen*sizeof(char));

	strcpy(temppath, path);
	strcat(temppath, TMP_SUFFIX);

	return temppath;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char* fullpath;
	fullpath = xmp_fullpath(path);

	int res = lsetxattr(fullpath, name, value, size, flags);


	if (res == -1)
		return -errno;
	free(fullpath);	
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char* fullpath;
	fullpath = xmp_fullpath(path);
	int res = lgetxattr(fullpath, name, value, size);

	if (res == -1)
		return -errno;
	free(fullpath);	
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char* fullpath;
	fullpath = xmp_fullpath(path);

	int res = llistxattr(fullpath, list, size);

	if (res == -1)
		return -errno;
	free(fullpath);	
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char* fullpath;
	fullpath = xmp_fullpath(path);

	int res = lremovexattr(fullpath, name);

	if (res == -1)
		return -errno;
	free(fullpath);	
	return 0;
}
#endif /* HAVE_SETXATTR */

int xmp_encryptfile(const char *path){
	    /* Local vars */
    int action = 0;
    FILE* inFile = NULL;
    FILE* outFile = NULL;
    char* key_str = NULL;

    char* fullpath;
    char* temppath;
    fullpath = xmp_fullpath(path);
    temppath = xmp_temppath(fullpath);

    /* Encrypt Case */

	/* Set Vars */
	key_str = XMP_DATA->key;
	action = 1;
    

    /* Open Files */
    inFile = fopen(fullpath, "rb");
	if(!inFile){
		perror("infile fopen error");
		return EXIT_FAILURE;
	}
    outFile = fopen(temppath, "wb+");
    if(!outFile){
		perror("outfile fopen error");
		return EXIT_FAILURE;
    }

    /* Perform do_crpt action (encrypt, decrypt, copy) */
    if(!do_crypt(inFile, outFile, action, key_str)){
		fprintf(stderr, "do_crypt failed\n");
    }

    /* Cleanup */
    if(fclose(outFile)){
        perror("outFile fclose error\n");
    }
    if(fclose(inFile)){
		perror("inFile fclose error\n");
    }

    //enc copy now at temppath, delete original and rename
    //delete
    unlink(fullpath);
    //rename
    rename(temppath, fullpath);

    //lazy want to sleeep
    char* truestring = "true";
    xmp_setxattr(path, XATTR_NAME, truestring, strlen(truestring), 0);

    free(fullpath);
    free(temppath);
    return 0;
}

int xmp_decryptfile(const char *path){
	    /* Local vars */
    int action = 0;
    FILE* inFile = NULL;
    FILE* outFile = NULL;
    char* key_str = NULL;

    char* fullpath;
    char* temppath;
    fullpath = xmp_fullpath(path);
    temppath = xmp_temppath(fullpath);

    /* Encrypt Case */

	/* Set Vars */
	key_str = XMP_DATA->key;
	action = 0;
    

    /* Open Files */
    inFile = fopen(fullpath, "rb");
	if(!inFile){
		perror("infile fopen error");
		return EXIT_FAILURE;
	}
    outFile = fopen(temppath, "wb+");
    if(!outFile){
		perror("outfile fopen error");
		return EXIT_FAILURE;
    }

    /* Perform do_crpt action (encrypt, decrypt, copy) */
    if(!do_crypt(inFile, outFile, action, key_str)){
		fprintf(stderr, "do_crypt failed\n");
    }

    /* Cleanup */
    if(fclose(outFile)){
        perror("outFile fclose error\n");
    }
    if(fclose(inFile)){
		perror("inFile fclose error\n");
    }


    //dec copy now at temppath, delete original and rename
    //delete
    unlink(fullpath);
    //rename
    rename(temppath, fullpath);

    //lazy want to sleeep
    char* truestring = "true";
    xmp_setxattr(path, XATTR_NAME, truestring, strlen(truestring), 0);

    free(fullpath);
    free(temppath);
    return 0;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);

	res = lstat(fullpath, stbuf);
	if (res == -1)
		return -errno;

	free(fullpath);

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);

	res = access(fullpath, mask);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);

	res = readlink(fullpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	free(fullpath);
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	char* fullpath;
	fullpath = xmp_fullpath(path);

	dp = opendir(fullpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	free(fullpath);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);

	fprintf(stderr, "%s\n", "mkdnode");

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fullpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fullpath, mode);
	else
		res = mknod(fullpath, mode, rdev);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);	

	res = mkdir(fullpath, mode);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);	

	res = unlink(fullpath);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);	

	res = rmdir(fullpath);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;
	char* fullfrom;
	char* fullto;
	
	fullfrom = xmp_fullpath(from);
	fullto = xmp_fullpath(to);

	res = symlink(fullfrom, fullto);
	if (res == -1)
		return -errno;

	free(fullfrom);
	free(fullto);
	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;
	char* fullfrom;
	char* fullto;
	
	fullfrom = xmp_fullpath(from);
	fullto = xmp_fullpath(to);

	res = rename(fullfrom, fullto);
	if (res == -1)
		return -errno;

	free(fullfrom);
	free(fullto);
	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;
	char* fullfrom;
	char* fullto;
	
	fullfrom = xmp_fullpath(from);
	fullto = xmp_fullpath(to);

	res = link(fullfrom, fullto);
	if (res == -1)
		return -errno;

	free(fullfrom);
	free(fullto);
	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);

	res = chmod(fullpath, mode);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);

	res = lchown(fullpath, uid, gid);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);

	res = truncate(fullpath, size);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char* fullpath;
	fullpath = xmp_fullpath(path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fullpath, tv);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);

	res = open(fullpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	free(fullpath);	
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);
	(void) fi;

	char valstring[5];

	//if encrypted, decrypt.
	xmp_getxattr(path, XATTR_NAME, valstring, 5);
	if(strcmp(valstring, "true") == 0){
		xmp_decryptfile(path);
	}

	fd = open(fullpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);

	//if was dec need to reencrypt
	if(strcmp(valstring, "true") == 0){
		xmp_encryptfile(path);
	}
	free(fullpath);	
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);
	char valstring[5];
	//if encrypted, decrypt.

	xmp_getxattr(path, XATTR_NAME, valstring, 5);
	if(strcmp(valstring, "true")==0){
		printf("\n\n VALSTRING IN WRITE: %s\n", valstring);

		xmp_decryptfile(path);
	}

	//check if file exists, if it doesn't, set valstring so it'll be enc
	//after write is complete.
	if(access(fullpath, F_OK)){
		printf("\n\n ACCESS FAIL IN WRITE: %s\n", valstring);

		strcpy(valstring,"true");
	}



	(void) fi;
	fd = open(fullpath, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
		//if was dec need to reencrypt
		//make sure xt attribute set, since lazy
	// xmp_getxattr(path, XATTR_NAME, valstring, 5);
	if(strcmp(valstring, "true")==0){
		printf("\n\n IN WRITE: VAL STRING IS: %s\n", valstring);
		xmp_encryptfile(path);
	}

	free(fullpath);	
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char* fullpath;
	fullpath = xmp_fullpath(path);

	res = statvfs(fullpath, stbuf);
	if (res == -1)
		return -errno;

	free(fullpath);
	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;
	char* fullpath;
	fullpath = xmp_fullpath(path);
	char* truestring = "true";

    int res;
    res = creat(fullpath, mode);

    xmp_encryptfile(path);

    //set xattr
    xmp_setxattr(path, XATTR_NAME, truestring, strlen(truestring), 0);
    if(res == -1)
		return -errno;

    close(res);
	free(fullpath);
    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}



static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create     = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
	.init		= xmp_init,
	.destroy 	= xmp_destroy,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	xmp_state *xmp_data;


	/* Check General Input */
    if(argc < 4){
	fprintf(stderr, "usage: %s %s\n", argv[0],
		"<key phrase> <mirror dir> <mount point>");
	exit(EXIT_FAILURE);
    }

	umask(0);

	xmp_data = malloc(sizeof(xmp_state));

	// Pull the rootdir out of the argument list and save it in my
    // internal data
    xmp_data -> rootdir = realpath(argv[argc-2], NULL);
    xmp_data -> key = strdup(argv[argc-3]);
    argv[argc-3] = argv[argc-1];
    argv[argc-2] = NULL;
    argv[argc-1] = NULL;
    argc-=2;

	return fuse_main(argc, argv, &xmp_oper, xmp_data);
}


/*
action

encrypt 1
decrypt 0
copy -1

do_crypt(inFile, outFile, action, key_str)

*/