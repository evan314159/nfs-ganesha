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

DELEGATIONS
==========================================================

On Linux 6.19 and later, FSAL_VFS (and FSAL_XFS) can grant NFSv4 read and
write delegations. On older kernels, and on other platforms, they grant none.

Delegations are off unless both Delegations in the NFSV4 block and the
export's Delegations option enable them. See
:doc:`ganesha-core-config <ganesha-core-config>`\(8) and
:doc:`ganesha-export-config <ganesha-export-config>`\(8).

Why enable them
    A client with a delegation can cache a file's data and attributes, and
    open and close it, without asking the server. This saves round
    trips for files used by one client at a time, such as home directories
    and project trees, and most of all over high latency links. A write
    delegation also lets the client cache writes until it closes the file.

How they work
    Each NFS delegation holds a kernel delegation (fcntl F_SETDELEG) of the
    same type on the file, so processes on the server, such as Samba or a
    shell, see it too. A process that opens the file in a conflicting way,
    truncates, renames, links or unlinks it, or changes its attributes or
    extended attributes, waits while Ganesha recalls the delegation and the
    client returns it, with any writes it has cached. Then the process goes
    ahead, and Ganesha drops what it has cached about the file.

What they cost
    That process may wait for up to fs.lease-break-time (45 seconds by
    default), if the client doesn't return the delegation. The kernel lets
    it go ahead then, whether or not the client did, so Ganesha revokes a
    delegation still not returned 5 seconds before that, rather than after
    the NFSv4 lease time. Lowering fs.lease-break-time shortens the longest
    wait, and gives clients less time to return their delegations.

Requirements
    Without the CAP_LEASE capability, Ganesha sets and releases the kernel
    delegations as the file's owner, which needs CAP_SETUID. Container
    runtimes such as Docker and containerd give CAP_SETUID by default but not
    CAP_LEASE. The fcntl calls need nothing added to the runtime's default
    seccomp profile.

See also
==============================
:doc:`ganesha-log-config <ganesha-log-config>`\(8)
:doc:`ganesha-core-config <ganesha-core-config>`\(8)
:doc:`ganesha-export-config <ganesha-export-config>`\(8)
