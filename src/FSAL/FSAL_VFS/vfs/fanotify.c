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
 * @file    FSAL_VFS/vfs/fanotify.c
 * @brief   Invalidate cached objects changed outside Ganesha
 *
 * With notify_local_changes set in the VFS block, VFS watches each directory
 * it has a handle for with fanotify. When a process other than Ganesha
 * changes the directory or a file in it, the event's file handle is turned
 * into the VFS handle of the object and passed to the invalidate upcall,
 * so MDCACHE fetches the attributes and directory entries again instead of
 * serving them until they expire.
 *
 * Implementation notes:
 *
 * Privilege. fanotify without CAP_SYS_ADMIN (Linux 5.13) allows only inode
 * marks, a bounded event queue and a bounded number of marks
 * (fs.fanotify.max_user_marks), and needs events to report file handles.
 * Filesystem marks would need CAP_SYS_ADMIN, so they are not used.
 *
 * Marks. Each directory has one inode mark with FAN_EVENT_ON_CHILD, so it
 * reports changes to its entries and to the files in it. VFS can have more
 * than one handle for a directory at a time (MDCACHE drops the duplicate),
 * so marks are counted in a tree keyed by the VFS handle: the first handle
 * adds the mark and the last one freed removes it. A mark holds a reference
 * on the inode, so a marked directory stays in the kernel's inode cache.
 * The kernel removes the mark itself when the directory is deleted. Handles
 * are created and freed with Ganesha's own credentials, which can read any
 * directory, as a mark requires.
 *
 * File systems. Every ZFS dataset, or other file system, that VFS claims
 * under an export is recorded with the f_fsid of its root, which is how
 * events identify it. When it is unclaimed, the marks left on it are
 * removed, so they don't keep it from being unmounted.
 *
 * Handles. Events carry the handle the kernel's export operations encode
 * for the object, which is what name_to_handle_at() returns, so
 * vfs_kernel_to_handle() gives the same VFS handle, and the same MDCACHE
 * key, as a LOOKUP of the object.
 *
 * Which objects. FAN_REPORT_DIR_FID makes an event report both the object
 * and its directory. The directory is invalidated only for entry events
 * (create, delete, rename); for a write or attribute change only the
 * object is.
 *
 * Ganesha's own changes. An unprivileged listener gets the process ID of an
 * event only when it caused the event itself, and 0 otherwise. Events with
 * Ganesha's process ID are dropped, since MDCACHE already knows about them.
 *
 * Exports. The upcall goes to the first export of the file system, as
 * GPFS's does. A file system is released once its last export unclaims
 * it, so the thread looks it up again by its Ganesha fsid, under fs_lock,
 * rather than keep a pointer to it (get_fsid_first_export_ref()).
 *
 * Thread. One fanotify group and one thread serve all marks. The thread
 * starts with the first claim and runs until the module is unloaded:
 * claims and unclaims hold fs_lock, which the thread takes, so an unclaim
 * can't wait for the thread.
 *
 * Limits. If a directory can't be marked (too many marks), or the event
 * queue overflows, the changes missed are served from the cache until it
 * expires, as without notify_local_changes.
 */

#include "config.h"

#include "fsal.h"
#include "fsal_up.h"
#include "../vfs_methods.h"

#ifdef LINUX
#include <sys/fanotify.h>
#endif

#if defined(LINUX) && defined(FAN_REPORT_DIR_FID)

#include <poll.h>
#include <sys/eventfd.h>
#include <sys/statfs.h>
#include <urcu-bp.h>
#include "avltree.h"
#include "gsh_list.h"
#include "export_mgr.h"
#include "FSAL/fsal_init.h"

#define VFS_FANOTIFY_EVENTS                                                   \
	(FAN_MODIFY | FAN_ATTRIB | FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | \
	 FAN_MOVED_TO | FAN_DELETE_SELF | FAN_MOVE_SELF | FAN_ONDIR |         \
	 FAN_EVENT_ON_CHILD)

/* Events that change a directory's entries */
#define VFS_FANOTIFY_DIR_EVENTS \
	(FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO)

/** @brief A claimed file system */
struct vfs_watched_fs {
	struct glist_head list;
	struct fsal_filesystem *fs;
	fsid_t fsid; /*< f_fsid of the root, as events report it */
};

/** @brief A marked directory */
struct vfs_watched_dir {
	struct avltree_node node;
	struct fsal_filesystem *fs;
	uint32_t refcount; /*< VFS handles for the directory */
	vfs_file_handle_t fh;
};

static pthread_mutex_t watch_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct glist_head watched_fs = GLIST_HEAD_INIT(watched_fs);
static struct avltree watched_dirs;
static int fan_fd = -1;
static int stop_fd = -1;
static pthread_t watch_thread;
static bool thread_running;
static bool fanotify_failed;
static bool marks_exhausted;

static int watched_dir_cmpf(const struct avltree_node *lhs,
			    const struct avltree_node *rhs)
{
	const struct vfs_watched_dir *l =
		avltree_container_of(lhs, struct vfs_watched_dir, node);
	const struct vfs_watched_dir *r =
		avltree_container_of(rhs, struct vfs_watched_dir, node);

	if (l->fh.handle_len != r->fh.handle_len)
		return l->fh.handle_len < r->fh.handle_len ? -1 : 1;

	return memcmp(l->fh.handle_data, r->fh.handle_data, l->fh.handle_len);
}

/**
 * @brief Find a claimed file system
 *
 * @note Must hold watch_mutex
 */
static struct vfs_watched_fs *find_fs(struct fsal_filesystem *fs)
{
	struct glist_head *glist;

	glist_for_each(glist, &watched_fs) {
		struct vfs_watched_fs *wfs =
			glist_entry(glist, struct vfs_watched_fs, list);

		if (wfs->fs == fs)
			return wfs;
	}

	return NULL;
}

/**
 * @brief Add or remove the mark on a directory
 *
 * @note Must hold watch_mutex
 *
 * @return 0 on success, an errno on failure.
 */
static int mark_dir(struct fsal_filesystem *fs, vfs_file_handle_t *fh,
		    unsigned int flags)
{
	fsal_errors_t fsal_error;
	int fd, rc = 0;

	fd = vfs_open_by_handle(fs, fh, O_RDONLY | O_DIRECTORY, &fsal_error);

	if (fd < 0)
		return -fd;

	if (fanotify_mark(fan_fd, flags, VFS_FANOTIFY_EVENTS, fd, NULL) != 0)
		rc = errno;

	close(fd);
	return rc;
}

/**
 * @brief Invalidate one object named by a fanotify file handle
 *
 * @param[in] fsid       The f_fsid the event reports
 * @param[in] kernel_fh  The object's handle
 */
static void invalidate_fid(const fsid_t *fsid,
			   const struct file_handle *kernel_fh)
{
	struct glist_head *glist;
	bool found = false;
	struct fsal_fsid__ fs_fsid;
	enum fsid_type fs_fsid_type;
	vfs_file_handle_t *fh;
	struct gsh_buffdesc key;
	struct gsh_export *gsh_export;
	struct fsal_export *fsal_export;
	fsal_status_t status;

	vfs_alloc_handle(fh);

	PTHREAD_MUTEX_lock(&watch_mutex);

	glist_for_each(glist, &watched_fs) {
		struct vfs_watched_fs *wfs =
			glist_entry(glist, struct vfs_watched_fs, list);

		if (memcmp(&wfs->fsid, fsid, sizeof(*fsid)) == 0) {
			found = vfs_kernel_to_handle(wfs->fs, kernel_fh, fh) ==
				0;
			fs_fsid = wfs->fs->fsid;
			fs_fsid_type = wfs->fs->fsid_type;
			break;
		}
	}

	PTHREAD_MUTEX_unlock(&watch_mutex);

	if (!found) {
		LogFullDebug(COMPONENT_FSAL_UP,
			     "Event on a file system not watched, fsid %x.%x",
			     fsid->__val[0], fsid->__val[1]);
		return;
	}

	/* The file system may be unclaimed and released from here on, so
	 * look it up again by its fsid.
	 */
	get_fsid_first_export_ref(&fs_fsid, fs_fsid_type, &gsh_export,
				  &fsal_export);

	if (gsh_export == NULL)
		return;

	key.addr = fh->handle_data;
	key.len = fh->handle_len;

	status = fsal_export->up_ops->invalidate(fsal_export->up_ops, &key,
						 FSAL_UP_INVALIDATE_CACHE);

	if (FSAL_IS_ERROR(status))
		LogDebug(COMPONENT_FSAL_UP, "Invalidate failed: %s",
			 fsal_err_txt(status));
	else
		LogFullDebug(COMPONENT_FSAL_UP, "Invalidated an object on %s",
			     fsal_export->root_fs->path);

	put_gsh_export(gsh_export);
}

/**
 * @brief Handle one fanotify event
 *
 * @param[in] meta  The event
 */
static void handle_event(const struct fanotify_event_metadata *meta)
{
	const char *info = (const char *)meta + meta->metadata_len;
	const char *end = (const char *)meta + meta->event_len;

	if (meta->mask & FAN_Q_OVERFLOW) {
		LogWarn(COMPONENT_FSAL_UP,
			"fanotify queue overflowed, changes made outside Ganesha may be served from cache until it expires");
		return;
	}

	LogFullDebug(COMPONENT_FSAL_UP, "Event mask 0x%llx pid %d",
		     (unsigned long long)meta->mask, (int)meta->pid);

	if (meta->pid == getpid())
		return;

	while (info + sizeof(struct fanotify_event_info_header) <= end) {
		const struct fanotify_event_info_fid *fid =
			(const struct fanotify_event_info_fid *)info;

		if (fid->hdr.len < sizeof(*fid) + sizeof(struct file_handle) ||
		    info + fid->hdr.len > end)
			break;

		if (fid->hdr.info_type == FAN_EVENT_INFO_TYPE_FID ||
		    (fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID &&
		     (meta->mask & VFS_FANOTIFY_DIR_EVENTS) != 0))
			invalidate_fid((const fsid_t *)&fid->fsid,
				       (const struct file_handle *)fid->handle);

		info += fid->hdr.len;
	}
}

static void *watch_thread_func(void *arg)
{
	char buf[8192] __attribute__((
		aligned(__alignof__(struct fanotify_event_metadata))));
	struct pollfd fds[2] = { { .fd = fan_fd, .events = POLLIN },
				 { .fd = stop_fd, .events = POLLIN } };

	SetNameFunction("vfs_fanotify");
	rcu_register_thread();

	while (true) {
		const struct fanotify_event_metadata *meta;
		ssize_t len;

		if (poll(fds, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			LogCrit(COMPONENT_FSAL_UP, "poll failed: %s",
				strerror(errno));
			break;
		}

		if (fds[1].revents != 0)
			break;

		len = read(fan_fd, buf, sizeof(buf));

		if (len < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			LogCrit(COMPONENT_FSAL_UP,
				"Reading fanotify events failed: %s",
				strerror(errno));
			break;
		}

		for (meta = (const struct fanotify_event_metadata *)buf;
		     FAN_EVENT_OK(meta, len);
		     meta = FAN_EVENT_NEXT(meta, len)) {
			if (meta->vers == FANOTIFY_METADATA_VERSION)
				handle_event(meta);
		}
	}

	rcu_unregister_thread();
	return NULL;
}

/**
 * @brief Create the fanotify group and start its thread
 *
 * @note Must hold watch_mutex
 *
 * @return 0 on success, an errno on failure.
 */
static int start_watching(void)
{
	int rc;

	fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK |
				       FAN_REPORT_FID | FAN_REPORT_DIR_FID,
			       O_RDONLY);

	if (fan_fd < 0)
		return errno;

	stop_fd = eventfd(0, EFD_CLOEXEC);

	if (stop_fd < 0) {
		rc = errno;
		goto close_fan;
	}

	avltree_init(&watched_dirs, watched_dir_cmpf, 0);

	rc = pthread_create(&watch_thread, NULL, watch_thread_func, NULL);

	if (rc != 0)
		goto close_stop;

	thread_running = true;
	return 0;

close_stop:
	close(stop_fd);
	stop_fd = -1;
close_fan:
	close(fan_fd);
	fan_fd = -1;
	return rc;
}

void vfs_fanotify_claim(struct fsal_filesystem *fs, struct fsal_export *exp,
			int root_fd)
{
	struct vfs_fsal_module *module =
		container_of(exp->fsal, struct vfs_fsal_module, module);
	struct vfs_watched_fs *wfs;
	struct statfs st;
	int rc;

	if (!module->notify_local_changes)
		return;

	if (fstatfs(root_fd, &st) != 0) {
		LogWarn(COMPONENT_FSAL_UP,
			"Not watching %s for changes: fstatfs failed: %s",
			fs->path, strerror(errno));
		return;
	}

	PTHREAD_MUTEX_lock(&watch_mutex);

	if (fanotify_failed)
		goto out;

	if (!thread_running) {
		rc = start_watching();

		if (rc != 0) {
			LogWarn(COMPONENT_FSAL_UP,
				"Can not watch for changes made outside Ganesha (needs Linux 5.13): %s",
				strerror(rc));
			fanotify_failed = true;
			goto out;
		}
	}

	wfs = gsh_calloc(1, sizeof(*wfs), MEM_COMP_FSAL);
	wfs->fs = fs;
	wfs->fsid = st.f_fsid;
	glist_add_tail(&watched_fs, &wfs->list);

	LogInfo(COMPONENT_FSAL_UP, "Watching %s (fsid %x.%x) for changes",
		fs->path, st.f_fsid.__val[0], st.f_fsid.__val[1]);

out:
	PTHREAD_MUTEX_unlock(&watch_mutex);
}

void vfs_fanotify_unclaim(struct fsal_filesystem *fs)
{
	struct vfs_watched_fs *wfs;
	struct avltree_node *node, *next;

	PTHREAD_MUTEX_lock(&watch_mutex);

	wfs = find_fs(fs);

	if (wfs == NULL)
		goto out;

	glist_del(&wfs->list);
	gsh_free(wfs, MEM_COMP_FSAL);

	/* Remove the marks still on the file system, while its root fd is
	 * open, so they don't keep it busy.
	 */
	for (node = avltree_first(&watched_dirs); node != NULL; node = next) {
		struct vfs_watched_dir *dir =
			avltree_container_of(node, struct vfs_watched_dir,
					     node);

		next = avltree_next(node);

		if (dir->fs != fs)
			continue;

		(void)mark_dir(fs, &dir->fh, FAN_MARK_REMOVE);
		avltree_remove(node, &watched_dirs);
		gsh_free(dir, MEM_COMP_FSAL);
	}

	LogInfo(COMPONENT_FSAL_UP, "No longer watching %s for changes",
		fs->path);

out:
	PTHREAD_MUTEX_unlock(&watch_mutex);
}

void vfs_fanotify_watch_handle(struct vfs_fsal_obj_handle *hdl)
{
	struct vfs_watched_dir key, *dir;
	struct avltree_node *node;
	int rc;

	if (hdl->obj_handle.type != DIRECTORY)
		return;

	memcpy(&key.fh, hdl->handle, sizeof(key.fh));

	PTHREAD_MUTEX_lock(&watch_mutex);

	if (find_fs(hdl->obj_handle.fs) == NULL)
		goto out;

	node = avltree_lookup(&key.node, &watched_dirs);

	if (node != NULL) {
		dir = avltree_container_of(node, struct vfs_watched_dir, node);
		dir->refcount++;
		hdl->fanotify_watched = true;
		goto out;
	}

	rc = mark_dir(hdl->obj_handle.fs, hdl->handle, FAN_MARK_ADD);

	if (rc == ENOSPC) {
		if (!marks_exhausted)
			LogWarn(COMPONENT_FSAL_UP,
				"Out of fanotify marks (fs.fanotify.max_user_marks), changes made outside Ganesha in directories not watched are served from cache until it expires");
		marks_exhausted = true;
		goto out;
	} else if (rc != 0) {
		LogDebug(COMPONENT_FSAL_UP,
			 "Could not watch a directory on %s: %s",
			 hdl->obj_handle.fs->path, strerror(rc));
		goto out;
	}

	dir = gsh_malloc(sizeof(*dir), MEM_COMP_FSAL);
	dir->fs = hdl->obj_handle.fs;
	dir->refcount = 1;
	memcpy(&dir->fh, hdl->handle, sizeof(dir->fh));
	avltree_insert(&dir->node, &watched_dirs);
	hdl->fanotify_watched = true;

out:
	PTHREAD_MUTEX_unlock(&watch_mutex);
}

void vfs_fanotify_unwatch_handle(struct vfs_fsal_obj_handle *hdl)
{
	struct vfs_watched_dir key, *dir;
	struct avltree_node *node;

	if (!hdl->fanotify_watched)
		return;

	memcpy(&key.fh, hdl->handle, sizeof(key.fh));

	PTHREAD_MUTEX_lock(&watch_mutex);

	/* Gone if the file system was unclaimed */
	node = avltree_lookup(&key.node, &watched_dirs);

	if (node == NULL)
		goto out;

	dir = avltree_container_of(node, struct vfs_watched_dir, node);

	if (--dir->refcount > 0)
		goto out;

	/* Fails if the directory was deleted, which removed the mark */
	(void)mark_dir(dir->fs, &dir->fh, FAN_MARK_REMOVE);
	avltree_remove(node, &watched_dirs);
	gsh_free(dir, MEM_COMP_FSAL);

out:
	PTHREAD_MUTEX_unlock(&watch_mutex);
}

MODULE_FINI void vfs_fanotify_fini(void)
{
	uint64_t one = 1;

	if (!thread_running)
		return;

	if (write(stop_fd, &one, sizeof(one)) != sizeof(one)) {
		LogCrit(COMPONENT_FSAL_UP,
			"Could not stop the fanotify thread: %s",
			strerror(errno));
		return;
	}

	pthread_join(watch_thread, NULL);
	close(stop_fd);
	close(fan_fd);
	thread_running = false;
}

#else /* LINUX && FAN_REPORT_DIR_FID */

void vfs_fanotify_claim(struct fsal_filesystem *fs, struct fsal_export *exp,
			int root_fd)
{
	struct vfs_fsal_module *module =
		container_of(exp->fsal, struct vfs_fsal_module, module);

	if (module->notify_local_changes)
		LogWarn(COMPONENT_FSAL_UP,
			"notify_local_changes is not supported on this platform");
}

void vfs_fanotify_unclaim(struct fsal_filesystem *fs)
{
}

void vfs_fanotify_watch_handle(struct vfs_fsal_obj_handle *hdl)
{
}

void vfs_fanotify_unwatch_handle(struct vfs_fsal_obj_handle *hdl)
{
}

#endif /* LINUX && FAN_REPORT_DIR_FID */
