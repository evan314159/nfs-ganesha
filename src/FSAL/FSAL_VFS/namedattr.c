// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright 2026 Evan Champion <evan.champion31@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/**
 * @file    FSAL_VFS/namedattr.c
 * @brief   NFSv4 named attributes backed by user.* extended attributes
 *
 * OPENATTR on a file or directory gives a named attribute directory, whose
 * entries are the object's "user." extended attributes with the prefix
 * removed. Each is opened, read and written like a small file: a WRITE
 * changes only the bytes it covers, and the extended attribute is rewritten
 * with the result.
 *
 * Implementation notes:
 *
 * Objects. Named attributes and their directory are struct vfs_attr_handle,
 * not struct vfs_fsal_obj_handle, with their own ops (attr_dir_ops and
 * named_attr_ops). The rest of VFS must check vfs_is_attr_obj() before
 * treating an object as a vfs_fsal_obj_handle.
 *
 * Handles. Neither kind of object exists in the filesystem, so their handles
 * are the parent's handle with a trailer: a hash of the attribute name for a
 * named attribute, and a byte saying which kind it is. vfs_set_attr_handle()
 * also sets a flag in the first byte of the handle. When a client sends the
 * handle back, vfs_create_handle() in handle.c sees the flag and passes the
 * handle to vfs_attr_create_handle() here, which removes the trailer and
 * looks for the extended attribute whose name has that hash. Fileids have
 * ATTR_FILEID_BIT set, so they never equal the inode number of a real file.
 *
 * Values. No fd is kept open on an extended attribute. Each READ, WRITE or
 * size change opens the parent by its handle and reads the whole value. A
 * WRITE or size change then changes the value in memory and writes all of it
 * back, holding value_lock so two of them can't overlap. A value can be at
 * most XATTR_SIZE_MAX bytes, the Linux limit for one extended attribute.
 *
 * Attributes. A named attribute's owner, group, permissions and times are
 * those of the parent; only its size is its own (see attr_getattrs_fd()).
 *
 * LINK and RENAME. RFC 8881 5.3 forbids both between a named attribute
 * directory and any other directory, which is NFS4ERR_XDEV. Each direction
 * is refused in a different place, because LINK calls the obj_ops of the
 * source object and RENAME calls the obj_ops of the source directory:
 *
 * - A link of a named attribute into another directory: named_attr_link().
 * - A link of a normal file into a named attribute directory: linkfile() in
 *   handle.c.
 * - A rename of a named attribute out of its directory: attr_dir_rename().
 * - A rename of a normal file into a named attribute directory:
 *   renamefile() in handle.c.
 *
 * LINK and RENAME within one named attribute directory are allowed by
 * RFC 8881 but return NFS4ERR_NOTSUPP, which it lists as a valid error for
 * both. Linux has no call to link or rename an extended attribute: a link
 * would need two names sharing one value, and a rename done as setxattr()
 * then removexattr() isn't atomic.
 *
 * No known client links a named attribute. macOS, which this was written
 * for and tested with, has no call to link an extended attribute, and
 * FreeBSD's linkat() refuses one with EINVAL. FreeBSD 15 does allow renaming
 * a named attribute within its directory (renameat() on an O_NAMEDATTR
 * directory), so that fails on a FreeBSD client.
 */

#include "config.h"

#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#ifdef LINUX
#include <linux/limits.h> /* for XATTR_SIZE_MAX, XATTR_NAME_MAX */
#endif
#include "fsal.h"
#include "fsal_convert.h"
#include "fsal_up.h"
#include "fsal_handle_syscalls.h"
#include "FSAL/fsal_commonlib.h"
#include "FSAL/fsal_localfs.h"
#include "vfs_methods.h"
#include "os/xattr.h"
#include "city.h"

/* Everything up to the #else at the end of this file uses Linux-only
 * interfaces: listxattr() and llistxattr() on paths, /proc/self/fd, and
 * XATTR_SIZE_MAX and XATTR_NAME_MAX from <linux/limits.h>. On other platforms
 * only the stub functions after the #else are built, and named attributes are
 * not supported.
 */
#ifdef LINUX

#define ATTR_PREFIX "user."
#define ATTR_PREFIX_LEN (sizeof(ATTR_PREFIX) - 1)

/* Last byte of the handle trailer */
#define ATTR_KIND_DIR 1
#define ATTR_KIND_NAMED 2

/* Fileids of named attribute objects have the top bit set, out of the way of
 * real inode numbers.
 */
#define ATTR_FILEID_BIT (1ULL << 63)

struct vfs_attr_handle {
	struct fsal_obj_handle obj_handle;
	/** This object's handle: the parent's plus the trailer */
	vfs_file_handle_t handle;
	/** The handle of the named attribute directory */
	vfs_file_handle_t dir_handle;
	/** The handle of the file or directory the attributes belong to */
	vfs_file_handle_t parent;
	bool parent_is_dir;
	/** The named attribute, without the prefix; NULL for the directory */
	char *name;
	struct fsal_share share;
	/** Open mode of a stateless open */
	struct vfs_fd fd;
	/** Serialises the read-modify-write of a value */
	pthread_mutex_t value_lock;
};

static struct fsal_obj_ops attr_dir_ops;
static struct fsal_obj_ops named_attr_ops;
static pthread_once_t attr_ops_once = PTHREAD_ONCE_INIT;

static void attr_ops_init(void);

static inline struct vfs_attr_handle *to_attr(struct fsal_obj_handle *obj_hdl)
{
	return container_of(obj_hdl, struct vfs_attr_handle, obj_handle);
}

/**
 * @brief Build the extended attribute name for a named attribute
 *
 * @return 0, or ENAMETOOLONG.
 */
static int attr_xname(const char *name, char *xname, size_t xname_size)
{
	int len = snprintf(xname, xname_size, ATTR_PREFIX "%s", name);

	return (len < 0 || len >= xname_size) ? ENAMETOOLONG : 0;
}

/**
 * @brief Whether an extended attribute name is a named attribute
 *
 * Only user.* attributes are, and only if the rest is a valid NFS name.
 */
static const char *attr_from_xname(const char *xname)
{
	const char *name;

	if (strncmp(xname, ATTR_PREFIX, ATTR_PREFIX_LEN) != 0)
		return NULL;

	name = xname + ATTR_PREFIX_LEN;

	if (name[0] == '\0' || strchr(name, '/') != NULL ||
	    strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return NULL;

	return name;
}

/**
 * @brief Open the object the named attributes belong to
 *
 * @return An fd, or -errno.
 */
static int attr_open_parent(struct vfs_attr_handle *hdl,
			    fsal_errors_t *fsal_error)
{
	return vfs_open_by_handle(hdl->obj_handle.fs, &hdl->parent,
				  hdl->parent_is_dir ? O_RDONLY | O_DIRECTORY
						     : O_RDONLY,
				  fsal_error);
}

/**
 * @brief Read the whole value of an extended attribute
 *
 * @param[in]  fd     Object it belongs to
 * @param[in]  xname  Its name
 * @param[out] value  Allocated value, to be freed by the caller
 * @param[out] len    Its length
 *
 * @return 0 or errno.
 */
static int attr_get_value(int fd, const char *xname, char **value, size_t *len)
{
	ssize_t size, got;
	char *buf;
	int err;

	for (;;) {
		size = fgetxattr(fd, xname, NULL, 0);

		if (size < 0)
			return errno;

		/* At least one byte, so there is always a buffer to free */
		buf = gsh_malloc(size + 1, MEM_COMP_FSAL);
		got = fgetxattr(fd, xname, buf, size);

		if (got >= 0) {
			*value = buf;
			*len = got;
			return 0;
		}

		err = errno;
		gsh_free(buf, MEM_COMP_FSAL);

		/* ERANGE: it grew after we asked its size, so ask again */
		if (err != ERANGE)
			return err;
	}
}

/**
 * @brief Whether an object has any named attributes
 *
 * Works with any kind of fd, including O_PATH ones, which flistxattr()
 * can't use, by listing through /proc/self/fd.
 *
 * @param[in]  fd    Object, or the directory containing it if path is set,
 *                   or AT_FDCWD if path is absolute
 * @param[in]  path  Name in that directory, or NULL
 * @param[out] any   Whether it has named attributes
 *
 * @return 0 or errno.
 */
static int attr_any_at(int fd, const char *path, bool *any)
{
	char proc_path[PATH_MAX];
	ssize_t size, got;
	char *list, *xname;
	bool follow;
	int err, len;

	*any = false;

	if (fd == AT_FDCWD)
		len = snprintf(proc_path, sizeof(proc_path), "%s", path);
	else if (path != NULL)
		len = snprintf(proc_path, sizeof(proc_path),
			       "/proc/self/fd/%d/%s", fd, path);
	else
		len = snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d",
			       fd);

	if (len < 0 || len >= sizeof(proc_path))
		return ENAMETOOLONG;

	/* /proc/self/fd/N is a link to the object, so follow it; but don't
	 * follow a name in a directory, which could be a symlink.
	 */
	follow = path == NULL || fd == AT_FDCWD;

	for (;;) {
		size = follow ? listxattr(proc_path, NULL, 0)
			      : llistxattr(proc_path, NULL, 0);

		if (size < 0)
			return errno;

		if (size == 0)
			return 0;

		list = gsh_malloc(size, MEM_COMP_FSAL);
		got = follow ? listxattr(proc_path, list, size)
			     : llistxattr(proc_path, list, size);

		if (got >= 0)
			break;

		err = errno;
		gsh_free(list, MEM_COMP_FSAL);

		if (err != ERANGE)
			return err;
	}

	for (xname = list; xname < list + got; xname += strlen(xname) + 1) {
		if (attr_from_xname(xname) != NULL) {
			*any = true;
			break;
		}
	}

	gsh_free(list, MEM_COMP_FSAL);
	return 0;
}

static int attr_any(int fd, bool *any)
{
	return attr_any_at(fd, NULL, any);
}

/**
 * @brief Allocate a named attribute directory or named attribute object
 *
 * @param[in] exp_hdl        Export
 * @param[in] fs             Filesystem of the parent
 * @param[in] parent         Handle of the parent
 * @param[in] parent_is_dir  Whether the parent is a directory
 * @param[in] name           Named attribute, NULL for the directory
 * @param[out] hdl_out       The new object
 *
 * @return FSAL status.
 */
static fsal_status_t attr_alloc(struct fsal_export *exp_hdl,
				struct fsal_filesystem *fs,
				const vfs_file_handle_t *parent,
				bool parent_is_dir, const char *name,
				struct vfs_attr_handle **hdl_out)
{
	struct vfs_attr_handle *hdl;
	size_t trailer = 1;
	uint64_t name_hash = 0, fileid;

	pthread_once(&attr_ops_once, attr_ops_init);

	if (name != NULL) {
		name_hash = CityHash64(name, strlen(name));
		trailer += sizeof(name_hash);
	}

	if (parent->handle_len + trailer > VFS_HANDLE_LEN) {
		LogDebug(
			COMPONENT_FSAL,
			"No room for a named attribute handle in a %u byte handle",
			parent->handle_len);
		return fsalstat(ERR_FSAL_NOTSUPP, 0);
	}

	hdl = gsh_calloc(1, sizeof(*hdl), MEM_COMP_FSAL);

	hdl->parent = *parent;
	hdl->parent_is_dir = parent_is_dir;

	hdl->handle = *parent;

	if (vfs_set_attr_handle(&hdl->handle) != 0) {
		gsh_free(hdl, MEM_COMP_FSAL);
		return fsalstat(ERR_FSAL_NOTSUPP, 0);
	}

	hdl->dir_handle = hdl->handle;
	hdl->dir_handle.handle_data[hdl->dir_handle.handle_len++] =
		ATTR_KIND_DIR;

	if (name != NULL) {
		memcpy(hdl->handle.handle_data + hdl->handle.handle_len,
		       &name_hash, sizeof(name_hash));
		hdl->handle.handle_len += sizeof(name_hash);
	}

	hdl->handle.handle_data[hdl->handle.handle_len++] =
		name != NULL ? ATTR_KIND_NAMED : ATTR_KIND_DIR;

	/* A hash of the handle: the same however the object is reached, and
	 * unlikely to collide within the filesystem.
	 */
	fileid = CityHash64((const char *)hdl->handle.handle_data,
			    hdl->handle.handle_len);

	fsal_obj_handle_init(&hdl->obj_handle, exp_hdl,
			     name != NULL ? REGULAR_FILE : DIRECTORY, true);
	hdl->obj_handle.fs = fs;
	hdl->obj_handle.fsid = fs->fsid;
	hdl->obj_handle.fileid = fileid | ATTR_FILEID_BIT;

	if (name != NULL) {
		hdl->name = gsh_strdup(name, MEM_COMP_FSAL);
		hdl->obj_handle.obj_ops = &named_attr_ops;
		init_fsal_fd(&hdl->fd.fsal_fd, FSAL_FD_GLOBAL,
			     op_ctx->fsal_export);
		hdl->fd.fd = -1;
		PTHREAD_MUTEX_init(&hdl->value_lock, NULL);
	} else {
		hdl->obj_handle.obj_ops = &attr_dir_ops;
	}

	*hdl_out = hdl;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static void attr_release(struct fsal_obj_handle *obj_hdl)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);

	fsal_obj_handle_fini(obj_hdl, true);

	if (hdl->name != NULL) {
		destroy_fsal_fd(&hdl->fd.fsal_fd);
		PTHREAD_MUTEX_destroy(&hdl->value_lock);
		gsh_free(hdl->name, MEM_COMP_FSAL);
	}

	gsh_free(hdl, MEM_COMP_FSAL);
}

/**
 * @brief Get the attributes of a named attribute object, using an fd of
 *        the parent
 *
 * They follow the parent: its owner, group, permissions and times. A named
 * attribute's size is that of its value.
 */
static fsal_status_t attr_getattrs_fd(struct vfs_attr_handle *hdl, int fd,
				      struct fsal_attrlist *attrs)
{
	char xname[XATTR_NAME_MAX + 1];
	struct stat st;
	ssize_t size = 0;
	uint32_t perms;
	int err;

	if (fstat(fd, &st) < 0) {
		err = errno;
		goto error;
	}

	if (hdl->name != NULL) {
		err = attr_xname(hdl->name, xname, sizeof(xname));

		if (err != 0)
			goto error;

		size = fgetxattr(fd, xname, NULL, 0);

		if (size < 0) {
			err = errno == ENODATA ? ESTALE : errno;
			goto error;
		}
	}

	posix2fsal_attributes_all(&st, attrs);

	attrs->fsid = hdl->obj_handle.fs->fsid;
	attrs->fileid = hdl->obj_handle.fileid;
	fsal_fs_set_mounted_on_fileid(hdl->obj_handle.fs, attrs);
	attrs->rawdev.major = 0;
	attrs->rawdev.minor = 0;

	perms = attrs->mode & (S_IRWXU | S_IRWXG | S_IRWXO);

	if (hdl->name != NULL) {
		attrs->type = EXTENDED_ATTR;
		attrs->mode = perms & ~(S_IXUSR | S_IXGRP | S_IXOTH);
		attrs->filesize = size;
		attrs->spaceused = size;
		attrs->numlinks = 1;
	} else {
		/* A directory: add search permission wherever it is readable */
		attrs->type = ATTR_DIRECTORY;
		attrs->mode = perms |
			      ((perms & (S_IRUSR | S_IRGRP | S_IROTH)) >> 2);
		attrs->filesize = 0;
		attrs->spaceused = 0;
		attrs->numlinks = 2;
	}

	/* Named attributes and their directory never have named attributes */
	attrs->named_attr = false;
	FSAL_SET_MASK(attrs->valid_mask, ATTR4_NAMED_ATTR);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);

error:
	if (attrs->request_mask & ATTR_RDATTR_ERR)
		attrs->valid_mask = ATTR_RDATTR_ERR;

	return posix2fsal_status(err);
}

static fsal_status_t attr_getattrs(struct fsal_obj_handle *obj_hdl,
				   struct fsal_attrlist *attrs)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	fsal_status_t status;
	int fd;

	fd = attr_open_parent(hdl, &fsal_error);

	if (fd < 0) {
		if (attrs->request_mask & ATTR_RDATTR_ERR)
			attrs->valid_mask = ATTR_RDATTR_ERR;

		return fsalstat(fsal_error, -fd);
	}

	status = attr_getattrs_fd(hdl, fd, attrs);
	close(fd);

	return status;
}

static fsal_status_t attr_handle_to_wire(const struct fsal_obj_handle *obj_hdl,
					 fsal_digesttype_t output_type,
					 struct gsh_buffdesc *fh_desc)
{
	const struct vfs_attr_handle *hdl =
		container_of(obj_hdl, struct vfs_attr_handle, obj_handle);

	switch (output_type) {
	case FSAL_DIGEST_NFSV3:
	case FSAL_DIGEST_NFSV4:
		if (fh_desc->len < hdl->handle.handle_len) {
			LogMajor(
				COMPONENT_FSAL,
				"Space too small for handle.  need %u, have %zu",
				hdl->handle.handle_len, fh_desc->len);
			return fsalstat(ERR_FSAL_TOOSMALL, 0);
		}
		memcpy(fh_desc->addr, hdl->handle.handle_data,
		       hdl->handle.handle_len);
		break;
	default:
		return fsalstat(ERR_FSAL_SERVERFAULT, 0);
	}

	fh_desc->len = hdl->handle.handle_len;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static void attr_handle_to_key(struct fsal_obj_handle *obj_hdl,
			       struct gsh_buffdesc *fh_desc)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);

	fh_desc->addr = hdl->handle.handle_data;
	fh_desc->len = hdl->handle.handle_len;
}

/**
 * @brief Allocate the object for a named attribute in this directory
 */
static fsal_status_t attr_new_named(struct vfs_attr_handle *dir,
				    const char *name,
				    struct vfs_attr_handle **hdl_out)
{
	return attr_alloc(op_ctx->fsal_export, dir->obj_handle.fs, &dir->parent,
			  dir->parent_is_dir, name, hdl_out);
}

/**
 * @brief Drop the cached attributes of the parent and the attribute directory
 *
 * Call after changing a named attribute. That changes the parent's ctime, from
 * which both their change attributes come, and creating the first or removing
 * the last changes the parent's named_attr.
 */
static void attr_changed(struct vfs_attr_handle *hdl)
{
	const struct fsal_up_vector *up_ops = op_ctx->fsal_export->up_ops;
	struct gsh_buffdesc parent = {
		.addr = hdl->parent.handle_data,
		.len = hdl->parent.handle_len,
	};
	struct gsh_buffdesc dir = {
		.addr = hdl->dir_handle.handle_data,
		.len = hdl->dir_handle.handle_len,
	};

	(void)up_ops->invalidate(up_ops, &parent, FSAL_UP_INVALIDATE_ATTRS);
	(void)up_ops->invalidate(up_ops, &dir, FSAL_UP_INVALIDATE_ATTRS);
}

/* Named attribute directory */

/**
 * @brief Look up a named attribute, or ".." for the object they belong to
 */
static fsal_status_t attr_dir_lookup(struct fsal_obj_handle *dir_hdl,
				     const char *path,
				     struct fsal_obj_handle **handle,
				     struct fsal_attrlist *attrs_out)
{
	struct vfs_attr_handle *dir = to_attr(dir_hdl);
	struct vfs_attr_handle *hdl;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	char xname[XATTR_NAME_MAX + 1];
	fsal_status_t status;
	int fd, err;

	*handle = NULL;

	if (strcmp(path, "..") == 0) {
		struct gsh_buffdesc desc = {
			.addr = dir->parent.handle_data,
			.len = dir->parent.handle_len,
		};

		return vfs_create_handle(op_ctx->fsal_export, &desc, handle,
					 attrs_out);
	}

	err = attr_xname(path, xname, sizeof(xname));

	if (err != 0)
		return posix2fsal_status(err);

	if (attr_from_xname(xname) == NULL)
		return fsalstat(ERR_FSAL_NOENT, 0);

	fd = attr_open_parent(dir, &fsal_error);

	if (fd < 0)
		return fsalstat(fsal_error, -fd);

	if (fgetxattr(fd, xname, NULL, 0) < 0) {
		err = errno == ENODATA ? ENOENT : errno;
		close(fd);
		return posix2fsal_status(err);
	}

	status = attr_new_named(dir, path, &hdl);

	if (!FSAL_IS_ERROR(status) && attrs_out != NULL) {
		status = attr_getattrs_fd(hdl, fd, attrs_out);

		if (FSAL_IS_ERROR(status))
			attr_release(&hdl->obj_handle);
	}

	close(fd);

	if (!FSAL_IS_ERROR(status))
		*handle = &hdl->obj_handle;

	return status;
}

/**
 * @brief List the named attributes
 *
 * Cookies are the attribute's position in the list plus 3, as 0 to 2 are
 * reserved.
 */
static fsal_status_t attr_dir_readdir(struct fsal_obj_handle *dir_hdl,
				      fsal_cookie_t *whence, void *dir_state,
				      fsal_readdir_cb cb, attrmask_t attrmask,
				      bool *eof)
{
	struct vfs_attr_handle *dir = to_attr(dir_hdl);
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	fsal_cookie_t start = whence != NULL ? *whence : 0;
	fsal_cookie_t cookie = 2;
	ssize_t size, got;
	char *list = NULL, *xname;
	int fd, err;

	*eof = true;

	fd = attr_open_parent(dir, &fsal_error);

	if (fd < 0)
		return fsalstat(fsal_error, -fd);

	for (;;) {
		size = flistxattr(fd, NULL, 0);

		if (size < 0) {
			status = posix2fsal_status(errno);
			goto out;
		}

		list = gsh_malloc(size + 1, MEM_COMP_FSAL);
		got = flistxattr(fd, list, size);

		if (got >= 0)
			break;

		err = errno;
		gsh_free(list, MEM_COMP_FSAL);
		list = NULL;

		if (err != ERANGE) {
			status = posix2fsal_status(err);
			goto out;
		}
	}

	for (xname = list; xname < list + got; xname += strlen(xname) + 1) {
		const char *name = attr_from_xname(xname);
		struct vfs_attr_handle *hdl;
		struct fsal_attrlist attrs;
		enum fsal_dir_result cb_rc;

		if (name == NULL)
			continue;

		if (++cookie <= start)
			continue;

		status = attr_new_named(dir, name, &hdl);

		if (FSAL_IS_ERROR(status))
			goto out;

		fsal_prepare_attrs(&attrs, attrmask);

		status = attr_getattrs_fd(hdl, fd, &attrs);

		if (FSAL_IS_ERROR(status)) {
			fsal_release_attrs(&attrs);
			attr_release(&hdl->obj_handle);

			if (status.major == ERR_FSAL_STALE) {
				/* Removed since we listed it */
				status = fsalstat(ERR_FSAL_NO_ERROR, 0);
				continue;
			}

			goto out;
		}

		cb_rc = cb(name, &hdl->obj_handle, &attrs, dir_state, cookie);

		fsal_release_attrs(&attrs);

		if (cb_rc >= DIR_READAHEAD) {
			*eof = false;
			break;
		}
	}

out:
	gsh_free(list, MEM_COMP_FSAL);
	close(fd);
	return status;
}

/**
 * @brief Remove a named attribute
 */
static fsal_status_t attr_dir_unlink(
	struct fsal_obj_handle *dir_hdl, struct fsal_obj_handle *obj_hdl,
	const char *name, struct fsal_attrlist *parent_pre_attrs_out,
	struct fsal_attrlist *parent_post_attrs_out)
{
	struct vfs_attr_handle *dir = to_attr(dir_hdl);
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	char xname[XATTR_NAME_MAX + 1];
	int fd, rc, err;

	err = attr_xname(name, xname, sizeof(xname));

	if (err != 0)
		return posix2fsal_status(err);

	fd = attr_open_parent(dir, &fsal_error);

	if (fd < 0)
		return fsalstat(fsal_error, -fd);

	if (!vfs_set_credentials(&op_ctx->creds, dir_hdl->fsal)) {
		close(fd);
		return posix2fsal_status(EPERM);
	}

	rc = fremovexattr(fd, xname);
	err = errno;

	vfs_restore_ganesha_credentials(dir_hdl->fsal);
	close(fd);

	if (rc < 0)
		return posix2fsal_status(err == ENODATA ? ENOENT : err);

	attr_changed(dir);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t named_attr_open_by_handle(struct fsal_obj_handle *obj_hdl,
					       struct state_t *state,
					       fsal_openflags_t openflags);
static fsal_status_t named_attr_update(struct vfs_attr_handle *hdl,
				       uint64_t offset, struct iovec *iov,
				       int iov_count, bool stable,
				       size_t *written);

/**
 * @brief Open or create a named attribute by name
 */
static fsal_status_t
attr_dir_open2(struct fsal_obj_handle *dir_hdl, struct state_t *state,
	       fsal_openflags_t openflags, enum fsal_create_mode createmode,
	       const char *name, struct fsal_attrlist *attrs_in,
	       fsal_verifier_t verifier, struct fsal_obj_handle **new_obj,
	       struct fsal_attrlist *attrs_out, bool *caller_perm_check,
	       struct fsal_attrlist *parent_pre_attrs_out,
	       struct fsal_attrlist *parent_post_attrs_out)
{
	struct vfs_attr_handle *dir = to_attr(dir_hdl);
	struct vfs_attr_handle *hdl;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	char xname[XATTR_NAME_MAX + 1];
	fsal_status_t status;
	bool exists, created = false;
	int fd, rc, err;

	*new_obj = NULL;

	if (name == NULL)
		return fsalstat(ERR_FSAL_ISDIR, 0);

	/* Exclusive create is not supported: there is nowhere to keep the
	 * verifier. RFC 8881 18.16.3 requires NFS4ERR_INVAL.
	 */
	if (createmode >= FSAL_EXCLUSIVE)
		return fsalstat(ERR_FSAL_INVAL, 0);

	err = attr_xname(name, xname, sizeof(xname));

	if (err != 0)
		return posix2fsal_status(err);

	fd = attr_open_parent(dir, &fsal_error);

	if (fd < 0)
		return fsalstat(fsal_error, -fd);

	exists = fgetxattr(fd, xname, NULL, 0) >= 0;

	if (!exists && errno != ENODATA) {
		status = posix2fsal_status(errno);
		goto out;
	}

	if (!exists && createmode == FSAL_NO_CREATE) {
		status = fsalstat(ERR_FSAL_NOENT, 0);
		goto out;
	}

	if (exists && createmode == FSAL_GUARDED) {
		status = fsalstat(ERR_FSAL_EXIST, 0);
		goto out;
	}

	if (!exists) {
		if (!vfs_set_credentials(&op_ctx->creds, dir_hdl->fsal)) {
			status = posix2fsal_status(EPERM);
			goto out;
		}

		rc = fsetxattr(fd, xname, "", 0, 0);
		err = errno;

		vfs_restore_ganesha_credentials(dir_hdl->fsal);

		if (rc < 0) {
			status = posix2fsal_status(err);
			goto out;
		}

		created = true;

		attr_changed(dir);
	}

	status = attr_new_named(dir, name, &hdl);

	if (FSAL_IS_ERROR(status))
		goto out;

	/* An existing attribute is truncated by the open; a new one is empty */
	status = named_attr_open_by_handle(&hdl->obj_handle, state,
					   created ? openflags & ~FSAL_O_TRUNC
						   : openflags);

	if (!FSAL_IS_ERROR(status) && attrs_out != NULL)
		status = attr_getattrs_fd(hdl, fd, attrs_out);

	if (FSAL_IS_ERROR(status)) {
		attr_release(&hdl->obj_handle);
		goto out;
	}

	/* The caller must still check access to an existing attribute */
	*caller_perm_check = !created;
	*new_obj = &hdl->obj_handle;

out:
	close(fd);
	return status;
}

/* Named attribute */

static struct vfs_fd *named_attr_fd(struct vfs_attr_handle *hdl,
				    struct state_t *state)
{
	if (state != NULL)
		return &container_of(state, struct vfs_state_fd, state)->vfs_fd;

	return &hdl->fd;
}

/**
 * @brief Take or change the share reservation of an open
 *
 * There is no file descriptor: the value is read and written through the
 * parent on each operation, so an open is just its mode and share. As in
 * vfs_open2_by_handle(), FSAL_O_TRUNC truncates the value only once the share
 * reservation is known not to conflict, under the same lock.
 */
static fsal_status_t named_attr_open_by_handle(struct fsal_obj_handle *obj_hdl,
					       struct state_t *state,
					       fsal_openflags_t openflags)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);
	struct vfs_fd *my_fd = named_attr_fd(hdl, state);
	fsal_openflags_t old_openflags;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	size_t written;

	PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

	old_openflags = my_fd->fsal_fd.openflags;

	if (state != NULL) {
		status = check_share_conflict(&hdl->share, openflags, false);

		if (FSAL_IS_ERROR(status))
			goto out;
	}

	if (openflags & FSAL_O_TRUNC) {
		status = named_attr_update(hdl, 0, NULL, 0, false, &written);

		if (FSAL_IS_ERROR(status))
			goto out;
	}

	if (state != NULL)
		update_share_counters(&hdl->share, old_openflags, openflags);

	my_fd->fsal_fd.openflags = FSAL_O_NFS_FLAGS(openflags);

out:
	PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);
	return status;
}

/**
 * @brief Undo named_attr_open_by_handle() for an open that then failed
 *
 * Gives back the share reservation and restores the open mode the state had
 * before, old_openflags, which the caller read before the open. Nothing can
 * have changed them in between: the caller holds the state's state_lock for
 * the whole open. A stateless open takes no share reservation, so there is
 * nothing to undo.
 */
static void named_attr_undo_open(struct vfs_attr_handle *hdl,
				 struct state_t *state,
				 fsal_openflags_t old_openflags,
				 fsal_openflags_t openflags)
{
	if (state == NULL)
		return;

	PTHREAD_RWLOCK_wrlock(&hdl->obj_handle.obj_lock);

	update_share_counters(&hdl->share, openflags, old_openflags);
	named_attr_fd(hdl, state)->fsal_fd.openflags = old_openflags;

	PTHREAD_RWLOCK_unlock(&hdl->obj_handle.obj_lock);
}

static fsal_status_t
named_attr_open2(struct fsal_obj_handle *obj_hdl, struct state_t *state,
		 fsal_openflags_t openflags, enum fsal_create_mode createmode,
		 const char *name, struct fsal_attrlist *attrs_in,
		 fsal_verifier_t verifier, struct fsal_obj_handle **new_obj,
		 struct fsal_attrlist *attrs_out, bool *caller_perm_check,
		 struct fsal_attrlist *parent_pre_attrs_out,
		 struct fsal_attrlist *parent_post_attrs_out)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);
	fsal_openflags_t old_openflags;
	fsal_status_t status;

	if (name != NULL)
		return fsalstat(ERR_FSAL_NOTDIR, 0);

	if (createmode >= FSAL_EXCLUSIVE)
		return fsalstat(ERR_FSAL_INVAL, 0);

	old_openflags = named_attr_fd(hdl, state)->fsal_fd.openflags;

	status = named_attr_open_by_handle(&hdl->obj_handle, state, openflags);

	if (FSAL_IS_ERROR(status))
		return status;

	if (attrs_out != NULL)
		status = attr_getattrs(obj_hdl, attrs_out);

	if (FSAL_IS_ERROR(status))
		named_attr_undo_open(hdl, state, old_openflags, openflags);

	return status;
}

static fsal_openflags_t named_attr_status2(struct fsal_obj_handle *obj_hdl,
					   struct state_t *state)
{
	return named_attr_fd(to_attr(obj_hdl), state)->fsal_fd.openflags;
}

static fsal_status_t named_attr_reopen2(struct fsal_obj_handle *obj_hdl,
					struct state_t *state,
					fsal_openflags_t openflags)
{
	return named_attr_open_by_handle(obj_hdl, state, openflags);
}

static fsal_status_t named_attr_close2(struct fsal_obj_handle *obj_hdl,
				       struct state_t *state)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);
	struct vfs_fd *my_fd = named_attr_fd(hdl, state);

	PTHREAD_RWLOCK_wrlock(&obj_hdl->obj_lock);

	if (state != NULL)
		update_share_counters(&hdl->share, my_fd->fsal_fd.openflags,
				      FSAL_O_CLOSED);

	my_fd->fsal_fd.openflags = FSAL_O_CLOSED;

	PTHREAD_RWLOCK_unlock(&obj_hdl->obj_lock);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t named_attr_close(struct fsal_obj_handle *obj_hdl)
{
	return fsalstat(ERR_FSAL_NOT_OPENED, 0);
}

/**
 * @brief Check that I/O is allowed by the share reservations
 *
 * Without a state, the I/O takes a share reservation for its duration, as
 * with any other VFS file.
 */
static fsal_status_t named_attr_start_io(struct vfs_attr_handle *hdl,
					 struct state_t *state,
					 fsal_openflags_t openflags,
					 bool bypass)
{
	if (state != NULL)
		return fsalstat(ERR_FSAL_NO_ERROR, 0);

	return check_share_conflict_and_update_locked(&hdl->obj_handle,
						      &hdl->share,
						      FSAL_O_CLOSED, openflags,
						      bypass);
}

static void named_attr_end_io(struct vfs_attr_handle *hdl,
			      struct state_t *state, fsal_openflags_t openflags)
{
	if (state == NULL)
		update_share_counters_locked(&hdl->obj_handle, &hdl->share,
					     openflags, FSAL_O_CLOSED);
}

static void named_attr_read2(struct fsal_obj_handle *obj_hdl, bool bypass,
			     fsal_async_cb done_cb,
			     struct fsal_io_arg *read_arg, void *caller_arg)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	char xname[XATTR_NAME_MAX + 1];
	fsal_status_t status;
	char *value = NULL;
	size_t len = 0, pos;
	int fd, err, i;

	if (read_arg->info != NULL) {
		/* Let fsal_read2 fall back for READ_PLUS */
		done_cb(obj_hdl, posix2fsal_status(ENOTSUP), read_arg,
			caller_arg);
		return;
	}

	status = named_attr_start_io(hdl, read_arg->state, FSAL_O_READ, bypass);

	if (FSAL_IS_ERROR(status)) {
		done_cb(obj_hdl, status, read_arg, caller_arg);
		return;
	}

	err = attr_xname(hdl->name, xname, sizeof(xname));

	if (err != 0) {
		status = posix2fsal_status(err);
		goto out;
	}

	fd = attr_open_parent(hdl, &fsal_error);

	if (fd < 0) {
		status = fsalstat(fsal_error, -fd);
		goto out;
	}

	err = attr_get_value(fd, xname, &value, &len);
	close(fd);

	if (err != 0) {
		status = posix2fsal_status(err == ENODATA ? ESTALE : err);
		goto out;
	}

	read_arg->io_amount = 0;
	pos = read_arg->offset;

	for (i = 0; i < read_arg->iov_count && pos < len; i++) {
		size_t n = MIN(read_arg->iov[i].iov_len, len - pos);

		memcpy(read_arg->iov[i].iov_base, value + pos, n);
		pos += n;
		read_arg->io_amount += n;
	}

	read_arg->end_of_file = pos >= len;
	status = fsalstat(ERR_FSAL_NO_ERROR, 0);

out:
	gsh_free(value, MEM_COMP_FSAL);
	named_attr_end_io(hdl, read_arg->state, FSAL_O_READ);
	done_cb(obj_hdl, status, read_arg, caller_arg);
}

/**
 * @brief Replace part of a value, or change its size
 *
 * Extended attributes can only be read and written whole, so both a WRITE and
 * a SETATTR of the size read the whole value, change it in memory and write
 * it back with XATTR_REPLACE.
 *
 * With iov set, this is a WRITE of the iov at offset: the value grows if the
 * write ends past it, and is otherwise left the same size. With iov NULL, it
 * is a SETATTR of the size to offset: the value is cut to offset, or extended
 * to it with zeros.
 *
 * @param[in] hdl     Named attribute
 * @param[in] offset  Where to write
 * @param[in] iov     Data to write, or NULL to set the size to offset
 * @param[in] iov_count  Number of iov
 * @param[in] stable  Whether to sync the change
 * @param[out] written   Bytes written
 *
 * @return FSAL status.
 */
static fsal_status_t named_attr_update(struct vfs_attr_handle *hdl,
				       uint64_t offset, struct iovec *iov,
				       int iov_count, bool stable,
				       size_t *written)
{
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	char xname[XATTR_NAME_MAX + 1];
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	char *value = NULL;
	size_t len = 0, count = 0, newlen;
	int fd, err, rc, i;

	err = attr_xname(hdl->name, xname, sizeof(xname));

	if (err != 0)
		return posix2fsal_status(err);

	for (i = 0; i < iov_count; i++)
		count += iov[i].iov_len;

	/* The new length: for a WRITE, the end of the data written; for a size
	 * change, the size asked for (passed as offset).
	 */
	newlen = iov != NULL ? offset + count : offset;

	if (newlen > XATTR_SIZE_MAX)
		return fsalstat(ERR_FSAL_FBIG, 0);

	fd = attr_open_parent(hdl, &fsal_error);

	if (fd < 0)
		return fsalstat(fsal_error, -fd);

	PTHREAD_MUTEX_lock(&hdl->value_lock);

	err = attr_get_value(fd, xname, &value, &len);

	if (err != 0) {
		status = posix2fsal_status(err == ENODATA ? ESTALE : err);
		goto out;
	}

	/* A WRITE that ends before the end of the value keeps the rest of the
	 * value, so the length stays the same. Only a size change can make the
	 * value shorter.
	 */
	if (iov != NULL && newlen < len)
		newlen = len;

	/* The value is getting longer, by a WRITE past its end or a larger
	 * size. Fill the new bytes with zeros; a WRITE then copies its data
	 * over its part of them.
	 */
	if (newlen > len) {
		value = gsh_realloc(value, newlen + 1, MEM_COMP_FSAL);
		memset(value + len, 0, newlen - len);
	}

	if (iov != NULL) {
		size_t pos = offset;

		for (i = 0; i < iov_count; i++) {
			memcpy(value + pos, iov[i].iov_base, iov[i].iov_len);
			pos += iov[i].iov_len;
		}
	}

	if (!vfs_set_credentials(&op_ctx->creds, hdl->obj_handle.fsal)) {
		status = posix2fsal_status(EPERM);
		goto out;
	}

	rc = fsetxattr(fd, xname, value, newlen, XATTR_REPLACE);
	err = errno;

	vfs_restore_ganesha_credentials(hdl->obj_handle.fsal);

	if (rc < 0) {
		status = posix2fsal_status(err == ENODATA ? ESTALE : err);
		goto out;
	}

	attr_changed(hdl);

	if (stable && fsync(fd) < 0)
		status = posix2fsal_status(errno);

	*written = count;

out:
	PTHREAD_MUTEX_unlock(&hdl->value_lock);
	gsh_free(value, MEM_COMP_FSAL);
	close(fd);
	return status;
}

static void named_attr_write2(struct fsal_obj_handle *obj_hdl, bool bypass,
			      fsal_async_cb done_cb,
			      struct fsal_io_arg *write_arg, void *caller_arg)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);
	fsal_status_t status;
	size_t written = 0;

	status = named_attr_start_io(hdl, write_arg->state, FSAL_O_WRITE,
				     bypass);

	if (FSAL_IS_ERROR(status)) {
		done_cb(obj_hdl, status, write_arg, caller_arg);
		return;
	}

	status = named_attr_update(hdl, write_arg->offset, write_arg->iov,
				   write_arg->iov_count, write_arg->fsal_stable,
				   &written);

	if (FSAL_IS_ERROR(status))
		write_arg->fsal_stable = false;

	write_arg->io_amount = written;

	named_attr_end_io(hdl, write_arg->state, FSAL_O_WRITE);
	done_cb(obj_hdl, status, write_arg, caller_arg);
}

static fsal_status_t named_attr_commit2(struct fsal_obj_handle *obj_hdl,
					off_t offset, size_t len)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	int fd;

	fd = attr_open_parent(hdl, &fsal_error);

	if (fd < 0)
		return fsalstat(fsal_error, -fd);

	if (fsync(fd) < 0)
		status = posix2fsal_status(errno);

	close(fd);
	return status;
}

/**
 * @brief Set attributes of a named attribute
 *
 * Only the size can be set. The other attributes of a named attribute are
 * those of its parent (see attr_getattrs_fd()), so asking to set any of them
 * returns NFS4ERR_ATTRNOTSUPP. Ignoring them instead would be wrong: when the
 * FSAL succeeds, nfs4_op_setattr() tells the client that every attribute in
 * the request was set. In testing with macOS 27 (setting, overwriting,
 * listing and removing extended attributes, cp -p, ditto, touch, chmod and
 * mv), the macOS client never asked to set them on a named attribute.
 */
static fsal_status_t named_attr_setattr2(struct fsal_obj_handle *obj_hdl,
					 bool bypass, struct state_t *state,
					 struct fsal_attrlist *attrib_set)
{
	struct vfs_attr_handle *hdl = to_attr(obj_hdl);
	fsal_status_t status;
	size_t written;

	if ((attrib_set->valid_mask & ~ATTR_SIZE) != 0)
		return fsalstat(ERR_FSAL_ATTRNOTSUPP, 0);

	if (!FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_SIZE))
		return fsalstat(ERR_FSAL_NO_ERROR, 0);

	status = named_attr_start_io(hdl, state, FSAL_O_WRITE, bypass);

	if (FSAL_IS_ERROR(status))
		return status;

	status = named_attr_update(hdl, attrib_set->filesize, NULL, 0, false,
				   &written);

	named_attr_end_io(hdl, state, FSAL_O_WRITE);
	return status;
}

static fsal_status_t named_attr_merge(struct fsal_obj_handle *orig_hdl,
				      struct fsal_obj_handle *dupe_hdl)
{
	return merge_share(orig_hdl, &to_attr(orig_hdl)->share,
			   &to_attr(dupe_hdl)->share);
}

static bool same_attr_dir(struct vfs_attr_handle *hdl,
			  struct fsal_obj_handle *dir_hdl)
{
	struct vfs_attr_handle *dir;

	if (dir_hdl->obj_ops != &attr_dir_ops)
		return false;

	dir = to_attr(dir_hdl);

	return dir->handle.handle_len == hdl->dir_handle.handle_len &&
	       memcmp(dir->handle.handle_data, hdl->dir_handle.handle_data,
		      dir->handle.handle_len) == 0;
}

/**
 * @brief Link a named attribute: not supported
 *
 * RFC 8881 18.9.3 requires NFS4ERR_XDEV for a link into any other directory.
 */
static fsal_status_t named_attr_link(
	struct fsal_obj_handle *obj_hdl, struct fsal_obj_handle *destdir_hdl,
	const char *name, struct fsal_attrlist *destdir_pre_attrs_out,
	struct fsal_attrlist *destdir_post_attrs_out)
{
	if (same_attr_dir(to_attr(obj_hdl), destdir_hdl))
		return fsalstat(ERR_FSAL_NOTSUPP, 0);

	return fsalstat(ERR_FSAL_XDEV, 0);
}

/**
 * @brief Rename a named attribute: not supported
 *
 * Extended attributes can't be renamed atomically. RFC 8881 5.3 forbids a
 * rename into any other directory, which is NFS4ERR_XDEV.
 */
static fsal_status_t attr_dir_rename(
	struct fsal_obj_handle *obj_hdl, struct fsal_obj_handle *olddir_hdl,
	const char *old_name, struct fsal_obj_handle *newdir_hdl,
	const char *new_name, struct fsal_attrlist *olddir_pre_attrs_out,
	struct fsal_attrlist *olddir_post_attrs_out,
	struct fsal_attrlist *newdir_pre_attrs_out,
	struct fsal_attrlist *newdir_post_attrs_out)
{
	if (newdir_hdl != olddir_hdl &&
	    !same_attr_dir(to_attr(obj_hdl), newdir_hdl))
		return fsalstat(ERR_FSAL_XDEV, 0);

	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}

static void attr_ops_init(void)
{
	fsal_default_obj_ops_init(&attr_dir_ops);

	attr_dir_ops.release = attr_release;
	attr_dir_ops.getattrs = attr_getattrs;
	attr_dir_ops.handle_to_wire = attr_handle_to_wire;
	attr_dir_ops.handle_to_key = attr_handle_to_key;
	attr_dir_ops.lookup = attr_dir_lookup;
	attr_dir_ops.readdir = attr_dir_readdir;
	attr_dir_ops.unlink = attr_dir_unlink;
	attr_dir_ops.open2 = attr_dir_open2;
	attr_dir_ops.rename = attr_dir_rename;

	fsal_default_obj_ops_init(&named_attr_ops);

	named_attr_ops.release = attr_release;
	named_attr_ops.getattrs = attr_getattrs;
	named_attr_ops.handle_to_wire = attr_handle_to_wire;
	named_attr_ops.handle_to_key = attr_handle_to_key;
	named_attr_ops.merge = named_attr_merge;
	named_attr_ops.open2 = named_attr_open2;
	named_attr_ops.status2 = named_attr_status2;
	named_attr_ops.reopen2 = named_attr_reopen2;
	named_attr_ops.close2 = named_attr_close2;
	named_attr_ops.close = named_attr_close;
	named_attr_ops.read2 = named_attr_read2;
	named_attr_ops.write2 = named_attr_write2;
	named_attr_ops.commit2 = named_attr_commit2;
	named_attr_ops.setattr2 = named_attr_setattr2;
	named_attr_ops.link = named_attr_link;
}

/**
 * @brief Whether an object is a named attribute or named attribute directory
 *
 * The rest of VFS assumes every object it is given is a struct
 * vfs_fsal_obj_handle. These objects are not, so it must check first.
 */
bool vfs_is_attr_obj(const struct fsal_obj_handle *obj_hdl)
{
	return obj_hdl->obj_ops == &attr_dir_ops ||
	       obj_hdl->obj_ops == &named_attr_ops;
}

/* Entry points from the rest of VFS */

/**
 * @brief Set whether an object has named attributes, if requested
 *
 * @param[in]     fd     Object (any kind of fd), or its directory if path
 *                       is set
 * @param[in]     path   Name in that directory, or NULL
 * @param[in,out] attrs  Attributes of the object, with its type
 */
void vfs_get_named_attr(int fd, const char *path, struct fsal_attrlist *attrs)
{
	bool any = false;

	if (!FSAL_TEST_MASK(attrs->request_mask, ATTR4_NAMED_ATTR) ||
	    !op_ctx->fsal_export->exp_ops.fs_supports(op_ctx->fsal_export,
						      fso_named_attr))
		return;

	/* Only files and directories have them */
	if ((attrs->type == REGULAR_FILE || attrs->type == DIRECTORY) &&
	    attr_any_at(fd, path, &any) != 0)
		return;

	attrs->named_attr = any;
	FSAL_SET_MASK(attrs->valid_mask, ATTR4_NAMED_ATTR);
}

fsal_status_t vfs_openattr(struct fsal_obj_handle *obj_hdl, bool createdir,
			   struct fsal_obj_handle **attrdir,
			   struct fsal_attrlist *attrs_out)
{
	struct vfs_fsal_obj_handle *myself =
		container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	struct vfs_attr_handle *hdl;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	fsal_status_t status;
	bool any;
	int fd, err;

	*attrdir = NULL;

	if (obj_hdl->type != REGULAR_FILE && obj_hdl->type != DIRECTORY)
		return fsalstat(ERR_FSAL_NOTSUPP, 0);

	if (!op_ctx->fsal_export->exp_ops.fs_supports(op_ctx->fsal_export,
						      fso_named_attr))
		return fsalstat(ERR_FSAL_NOTSUPP, 0);

	status = attr_alloc(op_ctx->fsal_export, obj_hdl->fs, myself->handle,
			    obj_hdl->type == DIRECTORY, NULL, &hdl);

	if (FSAL_IS_ERROR(status))
		return status;

	fd = attr_open_parent(hdl, &fsal_error);

	if (fd < 0) {
		status = fsalstat(fsal_error, -fd);
		goto err;
	}

	/* The directory exists if there is anything in it */
	if (!createdir) {
		err = attr_any(fd, &any);

		if (err != 0 || !any) {
			status = posix2fsal_status(err != 0 ? err : ENOENT);
			close(fd);
			goto err;
		}
	}

	if (attrs_out != NULL)
		status = attr_getattrs_fd(hdl, fd, attrs_out);

	close(fd);

	if (FSAL_IS_ERROR(status))
		goto err;

	*attrdir = &hdl->obj_handle;
	return status;

err:
	attr_release(&hdl->obj_handle);
	return status;
}

/**
 * @brief Make a named attribute object from its handle
 *
 * @param[in]  exp_hdl    Export
 * @param[in]  fs         Filesystem in the handle
 * @param[in]  fh         The handle, with the named attribute trailer
 * @param[out] handle     The object
 * @param[out] attrs_out  Optional attributes
 *
 * @return FSAL status.
 */
fsal_status_t vfs_attr_create_handle(struct fsal_export *exp_hdl,
				     struct fsal_filesystem *fs,
				     vfs_file_handle_t *fh,
				     struct fsal_obj_handle **handle,
				     struct fsal_attrlist *attrs_out)
{
	vfs_file_handle_t parent = *fh;
	struct vfs_attr_handle *hdl = NULL;
	fsal_errors_t fsal_error = ERR_FSAL_NO_ERROR;
	fsal_status_t status = { ERR_FSAL_NO_ERROR, 0 };
	uint64_t name_hash = 0;
	struct stat st;
	char *list = NULL, *xname;
	const char *name = NULL;
	ssize_t size, got;
	uint8_t kind;
	int fd, err;

	*handle = NULL;

	if (parent.handle_len < 2)
		return fsalstat(ERR_FSAL_BADHANDLE, 0);

	kind = parent.handle_data[--parent.handle_len];

	if (kind == ATTR_KIND_NAMED) {
		if (parent.handle_len < sizeof(name_hash) + 1)
			return fsalstat(ERR_FSAL_BADHANDLE, 0);

		parent.handle_len -= sizeof(name_hash);
		memcpy(&name_hash, parent.handle_data + parent.handle_len,
		       sizeof(name_hash));
	} else if (kind != ATTR_KIND_DIR) {
		return fsalstat(ERR_FSAL_BADHANDLE, 0);
	}

	vfs_clear_attr_handle(&parent);

	/* Not O_PATH: the XFS flavour can't open files by handle with it */
	fd = vfs_open_by_handle(fs, &parent, O_RDONLY, &fsal_error);

	if (fd < 0)
		return fsalstat(fsal_error, -fd);

	if (fstat(fd, &st) < 0) {
		status = posix2fsal_status(errno);
		close(fd);
		return status;
	}

	close(fd);

	if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
		return fsalstat(ERR_FSAL_STALE, 0);

	if (kind == ATTR_KIND_NAMED) {
		/* Find the attribute whose name has the hash */
		fd = vfs_open_by_handle(fs, &parent,
					S_ISDIR(st.st_mode)
						? O_RDONLY | O_DIRECTORY
						: O_RDONLY,
					&fsal_error);

		if (fd < 0)
			return fsalstat(fsal_error, -fd);

		for (;;) {
			size = flistxattr(fd, NULL, 0);

			if (size < 0) {
				status = posix2fsal_status(errno);
				goto out;
			}

			list = gsh_malloc(size + 1, MEM_COMP_FSAL);
			got = flistxattr(fd, list, size);

			if (got >= 0)
				break;

			err = errno;
			gsh_free(list, MEM_COMP_FSAL);
			list = NULL;

			if (err != ERANGE) {
				status = posix2fsal_status(err);
				goto out;
			}
		}

		for (xname = list; xname < list + got;
		     xname += strlen(xname) + 1) {
			const char *n = attr_from_xname(xname);

			if (n != NULL &&
			    CityHash64(n, strlen(n)) == name_hash) {
				name = n;
				break;
			}
		}

		if (name == NULL) {
			status = fsalstat(ERR_FSAL_STALE, 0);
			goto out;
		}
	} else {
		fd = -1;
	}

	status = attr_alloc(exp_hdl, fs, &parent, S_ISDIR(st.st_mode), name,
			    &hdl);

	if (!FSAL_IS_ERROR(status) && attrs_out != NULL) {
		status = attr_getattrs(&hdl->obj_handle, attrs_out);

		if (FSAL_IS_ERROR(status))
			attr_release(&hdl->obj_handle);
	}

	if (!FSAL_IS_ERROR(status))
		*handle = &hdl->obj_handle;

out:
	gsh_free(list, MEM_COMP_FSAL);

	if (fd >= 0)
		close(fd);

	return status;
}

#else /* LINUX */

/* Named attributes are not supported on this platform. OPENATTR returns
 * NFS4ERR_NOTSUPP, so no named attribute objects or handles are ever made,
 * and the rest of VFS is told that no object or handle is one.
 */

bool vfs_is_attr_obj(const struct fsal_obj_handle *obj_hdl)
{
	return false;
}

bool vfs_is_attr_handle(const vfs_file_handle_t *fh)
{
	return false;
}

void vfs_get_named_attr(int fd, const char *path, struct fsal_attrlist *attrs)
{
}

fsal_status_t vfs_openattr(struct fsal_obj_handle *obj_hdl, bool createdir,
			   struct fsal_obj_handle **attrdir,
			   struct fsal_attrlist *attrs_out)
{
	*attrdir = NULL;
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}

fsal_status_t vfs_attr_create_handle(struct fsal_export *exp_hdl,
				     struct fsal_filesystem *fs,
				     vfs_file_handle_t *fh,
				     struct fsal_obj_handle **handle,
				     struct fsal_attrlist *attrs_out)
{
	*handle = NULL;
	return fsalstat(ERR_FSAL_BADHANDLE, 0);
}

#endif /* LINUX */
