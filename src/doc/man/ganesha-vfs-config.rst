.. SPDX-License-Identifier: LGPL-3.0-or-later

===================================================================
ganesha-vfs-config -- NFS Ganesha VFS Configuration File
===================================================================

.. program:: ganesha-vfs-config


SYNOPSIS
==========================================================

| /etc/ganesha/vfs.conf

DESCRIPTION
==========================================================

NFS-Ganesha installs the config example for VFS FSAL:
| /etc/ganesha/vfs.conf

This file lists VFS specific config options.

EXPORT { FSAL {} }
--------------------------------------------------------------------------------

Name(string, "vfs")
    Name of FSAL should always be vfs.

**pnfs(bool, default false)**

fsid_type(enum)
	Possible values:
	None, One64, Major64, Two64, uuid, Two32, Dev,Device


VFS {}
--------------------------------------------------------------------------------

**link_support(bool, default true)**

**symlink_support(bool, default true)**

**cansettime(bool, default true)**

**maxread(uint64, range 512 to 64*1024*1024, default 64*1024*1024)**

**maxwrite(uint64, range 512 to 64*1024*1024, default 64*1024*1024)**

**umask(mode, range 0 to 07777, default 0)**

**auth_xdev_export(bool, default false)**

**only_one_user(bool, default false)**

**named_attr(bool, default false)**
    Support NFSv4 named attributes (OPENATTR). Each one is stored as a
    "user." extended attribute: the named attribute "foo" is the extended
    attribute "user.foo". A value can be at most the file system's
    extended attribute size (64 KiB on Linux). Linux only: elsewhere
    OPENATTR returns NFS4ERR_NOTSUPP.

macOS clients also need macOS_quirk_named_attr_NVERIFY and
macOS_quirk_named_attr_truncate in CLIENT blocks: see
:doc:`ganesha-export-config <ganesha-export-config>`\(8).

**notify_local_changes(bool, default false)**
    Linux only. Watch each directory Ganesha has cached with fanotify, and
    drop cached attributes and directory entries of objects that processes
    other than Ganesha change in it, instead of serving them until they
    expire. Covers every file system under the export that Ganesha reaches,
    such as nested ZFS datasets.

    Set it when files in the export also change on the server outside
    Ganesha, for instance through Samba, a shell or a backup restore, and
    NFS clients should see those changes at once. Without it they see them
    only once Attr_Expiration_Time (or the directory's) has passed, and
    lowering those instead makes Ganesha read attributes and directories
    from the file system far more often. Leave it off when only NFS clients
    change the files, as fanotify then only adds work.

    Costs: one fanotify mark for each directory in the cache, counted
    against fs.fanotify.max_user_marks for Ganesha's user; directories
    beyond that are not watched, and a warning is logged. A marked
    directory stays in the kernel's inode cache while Ganesha caches it.
    If the event queue overflows, the changes missed are served from the
    cache until it expires.

    Requirements: Linux 5.13 or later, and no capability beyond those
    Ganesha already needs. In a container, check the runtime's default
    seccomp profile. Some allow fanotify_init() only with CAP_SYS_ADMIN,
    which Ganesha doesn't need: at the time of writing Docker's and
    containerd's do, so Kubernetes' RuntimeDefault does on containerd, and
    CRI-O's doesn't. With such a runtime, use a profile that is the default
    plus fanotify_init (without CAP_SYS_ADMIN the kernel still allows only
    unprivileged fanotify). Otherwise Ganesha logs that it can not watch
    for changes and serves from the cache as without this option. Not
    supported by FSAL_XFS.

See also
==============================
:doc:`ganesha-log-config <ganesha-log-config>`\(8)
:doc:`ganesha-core-config <ganesha-core-config>`\(8)
:doc:`ganesha-export-config <ganesha-export-config>`\(8)
