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
 * @file    FSAL_VFS/deleg.c
 * @brief   NFSv4 delegations, backed by kernel delegations
 *
 * This file is Linux only. It needs kernel delegations (F_SETDELEG), which were
 * added in Linux 6.19. On other platforms and on older kernels,
 * vfs_deleg_supported() returns false, the FSAL grants no delegations, and the
 * stubs at the end of the file are used instead.
 *
 * How it works
 *
 * A kernel delegation is like a lease (F_SETLEASE), except that the kernel also
 * breaks it when the file is renamed, linked or unlinked, and, on the kernels
 * we tested (7.0 and 7.3), when its attributes or extended attributes change.
 * When we grant an NFS delegation, we also take a kernel delegation of the same
 * type on the file. A process on the server, such as Samba or a shell, that
 * wants to use the file in a way that conflicts with the delegation then has to
 * wait until the client returns it, just as another NFS client would.
 *
 * A kernel delegation belongs to an open file, so we take it on a dup() of the
 * fd of the open that the NFS delegation was granted with. The client may close
 * that open and keep the delegation, and the dup() keeps the kernel delegation
 * alive after that. A dup() also doesn't count as another open of the file.
 * That matters because the kernel only grants a write delegation while the file
 * has no other opens, and a read delegation while nobody has the file open for
 * writing.
 *
 * When a process conflicts with a kernel delegation, the kernel blocks the
 * process and sends a signal to the holder of the delegation. We send these
 * signals to one thread, deleg_thread(), which recalls the matching NFS
 * delegation. When the client returns it with DELEGRETURN, we release the
 * kernel delegation and the blocked process goes ahead. That process is about
 * to change the file, so we also invalidate the cached attributes and data.
 *
 * Ganesha's own use of the file
 *
 * The kernel makes no exception for the process holding the delegation. If
 * Ganesha opens or changes the file itself, it breaks its own delegation and
 * blocks. To avoid that:
 *
 * - READ, WRITE, COMMIT and reopens use a dup() of the delegation's fd instead
 *   of opening the file again (vfs_deleg_dup_fd(), called from find_fd() and
 *   vfs_reopen_func() in file.c).
 *
 * - Operations that change the file (setattr, rename, link, unlink and changes
 *   to extended attributes), or that have to open it again, release the kernel
 *   delegations first and take them back afterwards (vfs_deleg_suspend() and
 *   vfs_deleg_resume()). The NFS delegations stay in place. If a kernel
 *   delegation can't be taken back, because the file has since been opened in a
 *   conflicting way, we recall the NFS delegation. A change made by another
 *   process while the kernel delegations are released goes unnoticed, but that
 *   window only lasts for one operation.
 *
 * Clients that don't return a delegation
 *
 * The kernel only blocks the conflicting process for fs.lease-break-time (45
 * seconds by default). After that it lets the process go ahead, even though the
 * client still has the delegation. Ganesha normally waits for the NFSv4 lease
 * time before revoking a delegation, which is longer, so
 * vfs_fs_deleg_recall_limit() tells it to revoke the delegation a few seconds
 * before the kernel gives up.
 *
 * Permissions
 *
 * Without CAP_LEASE, only the owner of a file can set or release a delegation
 * on it, so we temporarily set the fsuid to the file's owner.
 *
 * Locking
 *
 * vfs_deleg_mutex protects every struct vfs_deleg, the lists they are on, and
 * each file's deleg_suspended count. We never take another lock while holding
 * it. Recalls and cache invalidations call back into SAL and MDCACHE, so we
 * copy what they need and queue them after releasing the mutex.
 */

#include "config.h"

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "fsal.h"
#include "fsal_convert.h"
#include "fsal_up.h"
#include "fridgethr.h"
#include "gsh_list.h"
#include "sal_data.h"
#include "vfs_methods.h"

#ifdef LINUX

#include <sys/fsuid.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>

/* F_GETDELEG and F_SETDELEG are new in Linux 6.19. C library headers often lag
 * the running kernel (Debian trixie's are from 6.12, and a container uses the
 * host's kernel), so define them here if missing. vfs_deleg_supported() checks
 * at startup whether the running kernel supports them. The values are from
 * linux/fcntl.h, where F_LINUX_SPECIFIC_BASE is 1024.
 */
#ifndef F_SETDELEG
#define F_GETDELEG (1024 + 15)
#define F_SETDELEG (1024 + 16)
#endif

/* Same layout as struct delegation in linux/fcntl.h. Older headers don't have
 * it, and linux/fcntl.h can't be included together with <fcntl.h>.
 */
struct vfs_deleg_arg {
	uint32_t d_flags;
	uint16_t d_type;
	uint16_t pad;
};

/* Setting a kernel delegation fails with EAGAIN both when the file is open in a
 * conflicting way and when another thread briefly holds the inode lock. Try a
 * few times before giving up, so the second case doesn't cost us the
 * delegation.
 */
#define VFS_DELEG_TRIES 3

/* The kernel lets a process blocked by a kernel delegation go ahead after
 * fs.lease-break-time seconds, 45 by default. We revoke the delegation
 * VFS_DELEG_REVOKE_MARGIN seconds before that. The margin covers the time it
 * takes to queue the recall, and the fact that Ganesha only checks for
 * delegations to revoke once a second.
 */
#define VFS_LEASE_BREAK_TIME "/proc/sys/fs/lease-break-time"
#define VFS_LEASE_BREAK_DEFAULT 45
#define VFS_DELEG_REVOKE_MARGIN 5

/** @brief An NFS delegation and the kernel delegation backing it */
struct vfs_deleg {
	/** Entry in the file's list, u.file.delegs */
	struct glist_head obj_list;
	/** Entry in the list of all delegations, vfs_delegs */
	struct glist_head all_list;
	/** The NFS delegation */
	struct state_t *state;
	struct vfs_fsal_obj_handle *myself;
	/** dup() of the open's fd, which holds the kernel delegation */
	int fd;
	/** F_RDLCK or F_WRLCK */
	short type;
	/** True while we hold the kernel delegation */
	bool held;
	/** True once a recall has been queued */
	bool recalled;
	/** True if the kernel broke it: another process wants the file */
	bool broken;
	/** Set by vfs_deleg_resume() on the ones to recall once it drops the
	 * mutex
	 */
	bool recall_now;
	/** For queueing the recall and the cache invalidation */
	const struct fsal_up_vector *up_ops;
	vfs_file_handle_t key;
};

/* Protects vfs_delegs, every file's delegs list and deleg_suspended count, and
 * the vfs_deleg entries themselves. Never take another lock while holding it.
 */
static pthread_mutex_t vfs_deleg_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct glist_head vfs_delegs = GLIST_HEAD_INIT(vfs_delegs);

static pthread_once_t vfs_deleg_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t vfs_deleg_tid_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t vfs_deleg_tid_cond = PTHREAD_COND_INITIALIZER;
/** Thread ID of deleg_thread(), which receives the break signals. 0 until it
 * has started, -1 if it couldn't start.
 */
static pid_t vfs_deleg_tid;

/**
 * @brief The signal the kernel sends us when it breaks a delegation
 *
 * We use a real-time signal because the kernel queues those instead of merging
 * them, so we see every break, and each one tells us the fd. We avoid SIGRTMIN
 * itself because some libraries use it. This is a function rather than a
 * constant because SIGRTMIN isn't a compile-time constant.
 */
static int vfs_deleg_signal(void)
{
	return SIGRTMIN + 1;
}

/**
 * @brief Set or release the kernel delegation on an fd
 *
 * Before setting one, this tells the kernel to send the break signal to
 * deleg_thread(). That has to be done every time, not just once per fd,
 * because releasing a delegation makes the kernel forget it (lease_modify()
 * clears the fd's owner and signal), and the next break would then send a
 * plain SIGIO that nothing receives.
 *
 * This runs with the fsuid set to the file's owner, because without CAP_LEASE
 * only the owner may do it.
 *
 * @param[in] fd    The fd
 * @param[in] type  F_RDLCK, F_WRLCK or F_UNLCK
 *
 * @return 0 or an errno.
 */
static int deleg_set(int fd, short type)
{
	struct vfs_deleg_arg arg = { .d_type = type };
	struct f_owner_ex owner = { .type = F_OWNER_TID, .pid = vfs_deleg_tid };
	struct stat st;
	int old_fsuid, rc, err = 0, tries = 0;

	if (type != F_UNLCK && (fcntl(fd, F_SETSIG, vfs_deleg_signal()) < 0 ||
				fcntl(fd, F_SETOWN_EX, &owner) < 0))
		return errno;

	if (fstat(fd, &st) < 0)
		return errno;

	old_fsuid = setfsuid(st.st_uid);

	do {
		rc = fcntl(fd, F_SETDELEG, &arg);
		err = rc < 0 ? errno : 0;
	} while (err == EAGAIN && type != F_UNLCK && ++tries < VFS_DELEG_TRIES);

	setfsuid(old_fsuid);

	return err;
}

/**
 * @brief Queue a recall of the NFS delegations on a file
 *
 * The recall runs later on a fridge thread, because it takes SAL locks that our
 * callers may already hold, and that must not be taken while holding
 * vfs_deleg_mutex.
 *
 * @param[in] deleg  The delegation, or a copy of it
 */
static void deleg_queue_recall(struct vfs_deleg *deleg)
{
	struct gsh_buffdesc key = {
		.addr = deleg->key.handle_data,
		.len = deleg->key.handle_len,
	};
	fsal_status_t status;

	status = up_async_delegrecall(general_fridge, deleg->up_ops, &key, NULL,
				      NULL);

	if (FSAL_IS_ERROR(status))
		LogCrit(COMPONENT_FSAL, "Could not queue delegation recall: %s",
			fsal_err_txt(status));
}

/**
 * @brief Thread that receives the kernel's break signals
 *
 * Each signal tells us which fd's delegation the kernel is breaking. We find
 * the matching delegation, mark it broken so that deleg_free() invalidates the
 * cache, and queue a recall the first time. A signal for an fd we no longer
 * hold a delegation on, for example one released while the signal was on its
 * way, is ignored.
 *
 * @param[in] arg  Unused
 *
 * @return NULL, if the thread couldn't set up signalfd().
 */
static void *deleg_thread(void *arg)
{
	struct signalfd_siginfo si;
	struct glist_head *glist;
	struct vfs_deleg *deleg, copy;
	sigset_t set;
	int sfd = -1;
	pid_t tid = -1;

	SetNameFunction("vfs_deleg");

	sigemptyset(&set);
	sigaddset(&set, vfs_deleg_signal());

	if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
		LogCrit(COMPONENT_FSAL, "Could not block delegation signal");
	} else {
		sfd = signalfd(-1, &set, SFD_CLOEXEC);

		if (sfd < 0)
			LogCrit(COMPONENT_FSAL, "signalfd failed: %s",
				strerror(errno));
		else
			tid = syscall(SYS_gettid);
	}

	PTHREAD_MUTEX_lock(&vfs_deleg_tid_mutex);
	vfs_deleg_tid = tid;
	pthread_cond_broadcast(&vfs_deleg_tid_cond);
	PTHREAD_MUTEX_unlock(&vfs_deleg_tid_mutex);

	if (sfd < 0)
		return NULL;

	for (;;) {
		ssize_t n = read(sfd, &si, sizeof(si));
		bool found = false;

		if (n != sizeof(si)) {
			if (n < 0 && errno == EINTR)
				continue;
			LogCrit(COMPONENT_FSAL, "Reading delegation signal: %s",
				n < 0 ? strerror(errno) : "short read");
			continue;
		}

		PTHREAD_MUTEX_lock(&vfs_deleg_mutex);

		glist_for_each(glist, &vfs_delegs) {
			deleg = glist_entry(glist, struct vfs_deleg, all_list);

			if (deleg->fd != (int)si.ssi_fd || !deleg->held)
				continue;

			deleg->broken = true;

			if (!deleg->recalled) {
				deleg->recalled = true;
				copy = *deleg;
				found = true;
			}
			break;
		}

		PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

		if (found) {
			LogDebug(COMPONENT_FSAL,
				 "Kernel delegation broken on fd %d, recalling",
				 copy.fd);
			deleg_queue_recall(&copy);
		}
	}

	return NULL;
}

/**
 * @brief Start deleg_thread() and wait for it to report its thread ID
 *
 * The first grant calls this through pthread_once(). If the thread can't start,
 * vfs_deleg_tid is set to -1 and no delegations are granted.
 */
static void deleg_start_thread(void)
{
	pthread_attr_t attr;
	pthread_t thread;
	int rc;

	PTHREAD_ATTR_init(&attr);
	PTHREAD_ATTR_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	rc = pthread_create(&thread, &attr, deleg_thread, NULL);

	PTHREAD_ATTR_destroy(&attr);

	PTHREAD_MUTEX_lock(&vfs_deleg_tid_mutex);

	if (rc != 0) {
		LogCrit(COMPONENT_FSAL, "Could not start delegation thread: %s",
			strerror(rc));
		vfs_deleg_tid = -1;
	}

	while (vfs_deleg_tid == 0)
		pthread_cond_wait(&vfs_deleg_tid_cond, &vfs_deleg_tid_mutex);

	PTHREAD_MUTEX_unlock(&vfs_deleg_tid_mutex);
}

/**
 * @brief How long a recalled delegation may go unreturned before it is revoked
 *
 * This is fs.lease-break-time minus VFS_DELEG_REVOKE_MARGIN. The sysctl is read
 * on every call, so a change to it takes effect without restarting Ganesha.
 *
 * @param[in] exp_hdl  Export (unused)
 *
 * @return Seconds.
 */
uint32_t vfs_fs_deleg_recall_limit(struct fsal_export *exp_hdl)
{
	unsigned int secs = VFS_LEASE_BREAK_DEFAULT;
	FILE *f = fopen(VFS_LEASE_BREAK_TIME, "re");

	if (f != NULL) {
		if (fscanf(f, "%u", &secs) != 1)
			secs = VFS_LEASE_BREAK_DEFAULT;
		fclose(f);
	}

	if (secs > 2 * VFS_DELEG_REVOKE_MARGIN)
		return secs - VFS_DELEG_REVOKE_MARGIN;

	/* lease-break-time is too short for the margin: use half of it */
	return secs > 1 ? secs / 2 : 1;
}

/**
 * @brief Check whether the running kernel supports delegations
 *
 * F_GETDELEG fails with EINVAL on kernels older than 6.19.
 *
 * @return true if it does.
 */
bool vfs_deleg_supported(void)
{
	struct vfs_deleg_arg arg = { 0 };
	int fd, rc;

	fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd < 0)
		return false;

	rc = fcntl(fd, F_GETDELEG, &arg);
	close(fd);

	return rc == 0;
}

/**
 * @brief Find the delegation for an NFS delegation state on a file
 *
 * @note The caller must hold vfs_deleg_mutex.
 *
 * @param[in] myself  The file
 * @param[in] state   The delegation state
 *
 * @return The delegation, or NULL.
 */
static struct vfs_deleg *deleg_find_locked(struct vfs_fsal_obj_handle *myself,
					   struct state_t *state)
{
	struct glist_head *glist;
	struct vfs_deleg *deleg;

	glist_for_each(glist, &myself->u.file.delegs) {
		deleg = glist_entry(glist, struct vfs_deleg, obj_list);

		if (deleg->state == state)
			return deleg;
	}

	return NULL;
}

/**
 * @brief Take a kernel delegation for a new NFS delegation
 *
 * We dup() the fd of the open the delegation is being granted with, ask the
 * kernel to send the break signal for it to deleg_thread(), and set the kernel
 * delegation on it. If the kernel refuses, because the file is open in a
 * conflicting way by Ganesha or anyone else, the NFS delegation isn't granted
 * either.
 *
 * @param[in] myself  The file
 * @param[in] state   The NFS delegation state
 * @param[in] type    F_RDLCK or F_WRLCK
 *
 * @return FSAL status. ERR_FSAL_DELAY if the open has already been closed.
 */
static fsal_status_t deleg_grant(struct vfs_fsal_obj_handle *myself,
				 struct state_t *state, short type)
{
	struct vfs_fd temp_fd = { FSAL_FD_INIT, -1 };
	struct fsal_fd *out_fd;
	struct vfs_deleg *deleg;
	fsal_status_t status;
	int fd = -1, err = 0;

	/* For a delegation state, fsal_start_io() returns the fd of the open
	 * the delegation was granted with.
	 */
	status = fsal_start_io(&out_fd, &myself->obj_handle,
			       &myself->u.file.fd.fsal_fd, &temp_fd.fsal_fd,
			       state,
			       type == F_WRLCK ? FSAL_O_ANY : FSAL_O_READ,
			       false, NULL, false, &myself->u.file.share);

	if (FSAL_IS_ERROR(status)) {
		LogDebug(COMPONENT_FSAL, "fsal_start_io failed returning %s",
			 fsal_err_txt(status));
		return status;
	}

	/* Only dup() the open's own fd. If we got the global fd or a temporary
	 * one instead, the open has already been closed.
	 */
	if (out_fd != &myself->u.file.fd.fsal_fd &&
	    out_fd != &temp_fd.fsal_fd) {
		fd = fcntl(container_of(out_fd, struct vfs_fd, fsal_fd)->fd,
			   F_DUPFD_CLOEXEC, 0);
		err = errno;
	}

	fsal_complete_io(&myself->obj_handle, out_fd);

	if (fd < 0) {
		LogDebug(COMPONENT_FSAL, "No fd of the delegation's open");
		return fsalstat(ERR_FSAL_DELAY, err);
	}

	pthread_once(&vfs_deleg_once, deleg_start_thread);

	if (vfs_deleg_tid < 0) {
		close(fd);
		return fsalstat(ERR_FSAL_NOTSUPP, 0);
	}

	err = deleg_set(fd, type);

	if (err != 0) {
		LogDebug(COMPONENT_FSAL, "No kernel delegation: %s",
			 strerror(err));
		close(fd);
		return posix2fsal_status(err);
	}

	deleg = gsh_calloc(1, sizeof(*deleg), MEM_COMP_FSAL);
	deleg->state = state;
	deleg->myself = myself;
	deleg->fd = fd;
	deleg->type = type;
	deleg->held = true;
	deleg->up_ops = myself->up_ops;
	deleg->key = *myself->handle;

	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);
	glist_add_tail(&myself->u.file.delegs, &deleg->obj_list);
	glist_add_tail(&vfs_delegs, &deleg->all_list);

	/* If another operation has the kernel delegations on this file released
	 * right now, release this one too. vfs_deleg_resume() will take it back
	 * along with the others.
	 */
	if (myself->u.file.deleg_suspended > 0) {
		deleg_set(fd, F_UNLCK);
		deleg->held = false;
	}

	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

	LogFullDebug(COMPONENT_FSAL, "%s delegation %p on fd %d for state %p",
		     type == F_WRLCK ? "Write" : "Read", deleg, fd, state);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/**
 * @brief Release the kernel delegation, close its fd and free the entry
 *
 * The caller must not hold vfs_deleg_mutex, because invalidating the cache
 * calls into MDCACHE.
 *
 * @param[in] deleg  The delegation, already removed from the lists
 */
static void deleg_free(struct vfs_deleg *deleg)
{
	struct gsh_buffdesc key = {
		.addr = deleg->key.handle_data,
		.len = deleg->key.handle_len,
	};
	fsal_status_t status;

	if (deleg->held)
		deleg_set(deleg->fd, F_UNLCK);

	close(deleg->fd);

	/* If another process broke the delegation, it is about to change the
	 * file, and nothing else will tell MDCACHE. Invalidate the cached
	 * attributes and data.
	 */
	if (deleg->broken) {
		status = up_async_invalidate(general_fridge, deleg->up_ops,
					     &key,
					     FSAL_UP_INVALIDATE_ATTRS |
						     FSAL_UP_INVALIDATE_CONTENT,
					     NULL, NULL);

		if (FSAL_IS_ERROR(status))
			LogCrit(COMPONENT_FSAL,
				"Could not queue cache invalidation: %s",
				fsal_err_txt(status));
	}

	gsh_free(deleg, MEM_COMP_FSAL);
}

/**
 * @brief Grant or release a delegation
 *
 * @param[in] obj_hdl  File on which to operate
 * @param[in] state    The delegation state
 * @param[in] owner    Owner of the delegation (unused)
 * @param[in] deleg    FSAL_DELEG_RD, FSAL_DELEG_WR or FSAL_DELEG_NONE
 *
 * @return FSAL status.
 */
fsal_status_t vfs_lease_op2(struct fsal_obj_handle *obj_hdl,
			    struct state_t *state, void *owner,
			    fsal_deleg_t deleg)
{
	struct vfs_fsal_obj_handle *myself =
		container_of(obj_hdl, struct vfs_fsal_obj_handle, obj_handle);
	struct vfs_deleg *found;

	if (obj_hdl->type != REGULAR_FILE)
		return fsalstat(ERR_FSAL_NOTSUPP, 0);

	switch (deleg) {
	case FSAL_DELEG_RD:
		return deleg_grant(myself, state, F_RDLCK);
	case FSAL_DELEG_WR:
		return deleg_grant(myself, state, F_WRLCK);
	case FSAL_DELEG_NONE:
		break;
	default:
		return fsalstat(ERR_FSAL_INVAL, 0);
	}

	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);

	found = deleg_find_locked(myself, state);

	if (found != NULL) {
		glist_del(&found->obj_list);
		glist_del(&found->all_list);
	}

	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

	LogFullDebug(COMPONENT_FSAL, "Release delegation %p for state %p",
		     found, state);

	if (found != NULL)
		deleg_free(found);

	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

/**
 * @brief vfs_deleg_suspend(), for callers that already hold vfs_deleg_mutex
 *
 * Calls can nest. Only the first one releases the kernel delegations, and
 * vfs_deleg_resume() only takes them back when the last one has finished.
 *
 * @param[in] myself  The file
 */
static void deleg_suspend_locked(struct vfs_fsal_obj_handle *myself)
{
	struct glist_head *glist;
	struct vfs_deleg *deleg;

	if (myself->u.file.deleg_suspended++ == 0) {
		glist_for_each(glist, &myself->u.file.delegs) {
			deleg = glist_entry(glist, struct vfs_deleg, obj_list);

			if (deleg->held) {
				deleg_set(deleg->fd, F_UNLCK);
				deleg->held = false;
				LogFullDebug(COMPONENT_FSAL,
					     "Suspended delegation %p", deleg);
			}
		}
	}
}

/**
 * @brief Release the kernel delegations on a file before Ganesha changes it
 *
 * Otherwise the change would break Ganesha's own delegations and block. Every
 * call must be followed by vfs_deleg_resume(). The NFS delegations stay granted
 * in the meantime, and a delegation granted in between only gets its kernel
 * delegation at the resume.
 *
 * @param[in] myself  The file
 */
void vfs_deleg_suspend(struct vfs_fsal_obj_handle *myself)
{
	if (myself->obj_handle.type != REGULAR_FILE)
		return;

	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);
	deleg_suspend_locked(myself);
	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);
}

/**
 * @brief vfs_deleg_resume(), for callers that already hold vfs_deleg_mutex
 *
 * The recalls can't be queued under the mutex, so this returns copies of the
 * delegations to recall, which the caller queues with deleg_queue_recall()
 * after dropping it, and then frees.
 *
 * @param[in]  myself  The file
 * @param[out] recall  Delegations to recall, or NULL
 *
 * @return How many delegations to recall.
 */
static int deleg_resume_locked(struct vfs_fsal_obj_handle *myself,
			       struct vfs_deleg **recall)
{
	struct glist_head *glist;
	struct vfs_deleg *deleg;
	int nrecall = 0, i = 0, err;

	*recall = NULL;

	if (--myself->u.file.deleg_suspended > 0)
		return 0;

	glist_for_each(glist, &myself->u.file.delegs) {
		deleg = glist_entry(glist, struct vfs_deleg, obj_list);

		if (deleg->held || deleg->recalled)
			continue;

		err = deleg_set(deleg->fd, deleg->type);

		if (err == 0) {
			deleg->held = true;
			LogFullDebug(COMPONENT_FSAL, "Resumed delegation %p",
				     deleg);
			continue;
		}

		LogDebug(COMPONENT_FSAL,
			 "Could not take %s delegation %p again: %s",
			 deleg->type == F_WRLCK ? "write" : "read", deleg,
			 strerror(err));
		deleg->recalled = true;
		deleg->recall_now = true;
		nrecall++;
	}

	if (nrecall == 0)
		return 0;

	*recall = gsh_calloc(nrecall, sizeof(**recall), MEM_COMP_FSAL);

	glist_for_each(glist, &myself->u.file.delegs) {
		deleg = glist_entry(glist, struct vfs_deleg, obj_list);

		if (deleg->recall_now) {
			deleg->recall_now = false;
			(*recall)[i++] = *deleg;
		}
	}

	return nrecall;
}

/* Queue the recalls deleg_resume_locked() returned, and free the copies */
static void deleg_queue_recalls(struct vfs_deleg *recall, int nrecall)
{
	int i;

	for (i = 0; i < nrecall; i++)
		deleg_queue_recall(&recall[i]);

	gsh_free(recall, MEM_COMP_FSAL);
}

/**
 * @brief Take the kernel delegations on a file back after changing it
 *
 * If the kernel won't give one back, because the file is now open in a
 * conflicting way, we recall that NFS delegation.
 *
 * @param[in] myself  The file
 */
void vfs_deleg_resume(struct vfs_fsal_obj_handle *myself)
{
	struct vfs_deleg *recall;
	int nrecall;

	if (myself->obj_handle.type != REGULAR_FILE)
		return;

	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);
	nrecall = deleg_resume_locked(myself, &recall);
	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

	deleg_queue_recalls(recall, nrecall);
}

/**
 * @brief Find the delegated file with a handle
 *
 * @note The caller must hold vfs_deleg_mutex.
 *
 * @param[in] fh  The handle
 *
 * @return The file, or NULL if no delegated file has that handle.
 */
static struct vfs_fsal_obj_handle *
deleg_find_handle_locked(const vfs_file_handle_t *fh)
{
	struct glist_head *glist;
	struct vfs_deleg *deleg;

	glist_for_each(glist, &vfs_delegs) {
		deleg = glist_entry(glist, struct vfs_deleg, all_list);

		if (deleg->key.handle_len == fh->handle_len &&
		    memcmp(deleg->key.handle_data, fh->handle_data,
			   fh->handle_len) == 0)
			return deleg->myself;
	}

	return NULL;
}

/**
 * @brief Release the kernel delegations of a file known only by its handle
 *
 * This is for code that changes a file without having its object handle,
 * such as named attributes, which only keep the handle of the file they
 * belong to. vfs_deleg_resume_handle() takes them back afterwards.
 *
 * @param[in] fh  The file's handle
 *
 * @return true if the file had delegations, and so needs
 *         vfs_deleg_resume_handle().
 */
bool vfs_deleg_suspend_handle(const vfs_file_handle_t *fh)
{
	struct vfs_fsal_obj_handle *myself;

	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);

	myself = deleg_find_handle_locked(fh);

	if (myself != NULL)
		deleg_suspend_locked(myself);

	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

	return myself != NULL;
}

/**
 * @brief Take back the kernel delegations vfs_deleg_suspend_handle() released
 *
 * The file is looked up again by its handle rather than kept from the
 * suspend, because its object handle may have been freed in between, for
 * example when a rename or unlink removed the file. Its delegations were
 * freed with it then, so there is nothing to take back.
 *
 * @param[in] fh  The file's handle
 */
void vfs_deleg_resume_handle(const vfs_file_handle_t *fh)
{
	struct vfs_fsal_obj_handle *myself;
	struct vfs_deleg *recall = NULL;
	int nrecall = 0;

	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);

	myself = deleg_find_handle_locked(fh);

	if (myself != NULL && myself->u.file.deleg_suspended > 0)
		nrecall = deleg_resume_locked(myself, &recall);

	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

	deleg_queue_recalls(recall, nrecall);
}

/**
 * @brief Release the kernel delegations of a file known only by name
 *
 * This is for the file that a rename replaces, which we have no handle for.
 *
 * @param[in]  dirfd  The directory
 * @param[in]  fs     Its file system
 * @param[in]  name   The name
 * @param[out] fh     The file's handle, for vfs_deleg_resume_handle()
 *
 * @return true if the file had delegations, and so needs
 *         vfs_deleg_resume_handle().
 */
bool vfs_deleg_suspend_name(int dirfd, struct fsal_filesystem *fs,
			    const char *name, vfs_file_handle_t *fh)
{
	/* Usually nothing is delegated, so skip looking up the name */
	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);
	if (glist_empty(&vfs_delegs)) {
		PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);
		return false;
	}
	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

	if (vfs_name_to_handle(dirfd, fs, name, fh) < 0)
		return false;

	return vfs_deleg_suspend_handle(fh);
}

/**
 * @brief Get an fd for a delegated file without opening it again
 *
 * Opening the file again could break Ganesha's own delegation, but a dup() of
 * the delegation's fd isn't a new open.
 *
 * @param[in] myself     The file
 * @param[in] openflags  The access needed
 *
 * @return A dup() of the fd of a delegation whose open allows the access, or -1
 *         if there isn't one.
 */
int vfs_deleg_dup_fd(struct vfs_fsal_obj_handle *myself,
		     fsal_openflags_t openflags)
{
	struct glist_head *glist;
	struct vfs_deleg *deleg;
	bool read = (openflags & FSAL_O_READ) != 0;
	bool write = (openflags & FSAL_O_WRITE) != 0;
	int fd = -1, mode;

	if (myself->obj_handle.type != REGULAR_FILE)
		return -1;

	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);

	glist_for_each(glist, &myself->u.file.delegs) {
		deleg = glist_entry(glist, struct vfs_deleg, obj_list);

		/* Skip delegations whose open doesn't allow the access we need
		 */
		mode = fcntl(deleg->fd, F_GETFL);

		if (mode < 0 || (read && (mode & O_ACCMODE) == O_WRONLY) ||
		    (write && (mode & O_ACCMODE) == O_RDONLY))
			continue;

		fd = fcntl(deleg->fd, F_DUPFD_CLOEXEC, 0);
		break;
	}

	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

	LogFullDebug(COMPONENT_FSAL, "dup of a delegation fd for %p: %d",
		     myself, fd);

	return fd;
}

/**
 * @brief vfs_deleg_dup_fd() for a file known only by its handle
 *
 * Named attributes use this to read and change the xattrs of the file they
 * belong to, because opening that file again would break a write delegation
 * on it. Unlike vfs_deleg_dup_fd(), any delegation's fd will do, because
 * xattr calls don't care how the fd was opened.
 *
 * @param[in] fh  The file's handle
 *
 * @return A dup() of a delegation's fd, or -1 if the file has no delegations.
 */
int vfs_deleg_dup_fd_handle(const vfs_file_handle_t *fh)
{
	struct vfs_fsal_obj_handle *myself;
	struct vfs_deleg *deleg;
	int fd = -1;

	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);

	myself = deleg_find_handle_locked(fh);

	if (myself != NULL) {
		deleg = glist_first_entry(&myself->u.file.delegs,
					  struct vfs_deleg, obj_list);
		if (deleg != NULL)
			fd = fcntl(deleg->fd, F_DUPFD_CLOEXEC, 0);
	}

	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

	return fd;
}

/**
 * @brief Free any delegations still left on a file when its handle is released
 *
 * @param[in] myself  The file
 */
void vfs_deleg_release(struct vfs_fsal_obj_handle *myself)
{
	struct glist_head *glist, *next;
	struct vfs_deleg *deleg;
	struct glist_head gone = GLIST_HEAD_INIT(gone);

	if (myself->obj_handle.type != REGULAR_FILE)
		return;

	PTHREAD_MUTEX_lock(&vfs_deleg_mutex);

	glist_for_each_safe(glist, next, &myself->u.file.delegs) {
		deleg = glist_entry(glist, struct vfs_deleg, obj_list);
		glist_del(&deleg->obj_list);
		glist_del(&deleg->all_list);
		glist_add_tail(&gone, &deleg->obj_list);
	}

	PTHREAD_MUTEX_unlock(&vfs_deleg_mutex);

	glist_for_each_safe(glist, next, &gone) {
		deleg = glist_entry(glist, struct vfs_deleg, obj_list);
		glist_del(&deleg->obj_list);
		deleg_free(deleg);
	}
}

#else /* LINUX */

/* No kernel delegations on this platform, so grant none */

uint32_t vfs_fs_deleg_recall_limit(struct fsal_export *exp_hdl)
{
	return 0;
}

bool vfs_deleg_supported(void)
{
	return false;
}

fsal_status_t vfs_lease_op2(struct fsal_obj_handle *obj_hdl,
			    struct state_t *state, void *owner,
			    fsal_deleg_t deleg)
{
	return fsalstat(ERR_FSAL_NOTSUPP, 0);
}

void vfs_deleg_suspend(struct vfs_fsal_obj_handle *myself)
{
}

void vfs_deleg_resume(struct vfs_fsal_obj_handle *myself)
{
}

bool vfs_deleg_suspend_handle(const vfs_file_handle_t *fh)
{
	return false;
}

int vfs_deleg_dup_fd_handle(const vfs_file_handle_t *fh)
{
	return -1;
}

void vfs_deleg_resume_handle(const vfs_file_handle_t *fh)
{
}

bool vfs_deleg_suspend_name(int dirfd, struct fsal_filesystem *fs,
			    const char *name, vfs_file_handle_t *fh)
{
	return false;
}

int vfs_deleg_dup_fd(struct vfs_fsal_obj_handle *myself,
		     fsal_openflags_t openflags)
{
	return -1;
}

void vfs_deleg_release(struct vfs_fsal_obj_handle *myself)
{
}

#endif /* LINUX */
