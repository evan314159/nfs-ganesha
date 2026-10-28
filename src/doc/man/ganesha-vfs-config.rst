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
    such as nested ZFS datasets. Needs Linux 5.13 or later, and no extra
    capability. Each watched directory uses one fanotify mark, up to
    fs.fanotify.max_user_marks; directories beyond that are not watched.

See also
==============================
:doc:`ganesha-log-config <ganesha-log-config>`\(8)
:doc:`ganesha-core-config <ganesha-core-config>`\(8)
:doc:`ganesha-export-config <ganesha-export-config>`\(8)
