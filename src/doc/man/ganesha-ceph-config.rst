.. SPDX-License-Identifier: LGPL-3.0-or-later

===================================================================
ganesha-ceph-config -- NFS Ganesha CEPH Configuration File
===================================================================

.. program:: ganesha-ceph-config


SYNOPSIS
==========================================================

| /etc/ganesha/ceph.conf

DESCRIPTION
==========================================================

NFS-Ganesha install config example for CEPH FSAL:
| /etc/ganesha/ceph.conf

This file lists CEPH specific config options.

EXPORT { FSAL {} }
--------------------------------------------------------------------------------
Name(string, "Ceph")
    Name of FSAL should always be Ceph.

Filesystem(string, no default)
    Ceph filesystem name string, for mounting an alternate filesystem within
    the cluster. The default is to mount the default filesystem in the cluster
    (usually, the first one created).

User_Id(string, no default)
    cephx userid used to open the MDS session. This string is what gets appended
    to "client.". If not set, the ceph client libs will sort this out based on
    ceph configuration.

Secret_Access_Key(string, no default)
    Key to use for the session (if any). If not set, then it uses the normal
    search path for cephx keyring files to find a key.

sec_label_xattr(char, default "security.selinux xattr of the file")
    Enable NFSv4.2 security label attribute. Ganesha supports
    "Limited Server Mode" as detailed in RFC 7204. Note that
    not all FSALs support security labels.

cmount_path(string, no default)
    If specified, the path within the ceph filesystem to mount this
    export on. It is allowed to be any complete path hierarchy between `/` and
    the EXPORT {path}. (i.e. if EXPORT { Path } parameter is `/foo/bar` then
    cmount_path could be `/`, `/foo` or `/foo/bar`).

    If this and the other EXPORT { FSAL {} } options are the same
    between multiple exports, those exports will share a single
    cephfs client. With the default, this effectively defaults to
    the same path as EXPORT { Path }.

CEPH {}
--------------------------------------------------------------------------------

Ceph_Conf(path, default "")
    Path to the ceph config file to inherit ceph configuration from.

umask(mode, range 0 to 07777, default 0)

client_oc(bool, default false)
    Enable or disable client_oc (object cache). This defaults to false because
    Ganesha runs better with it disabled.

client_oc_size(uint64, range 0 to UINT64_MAX, default 209715200)
    Sets the size of object cache to the provided size. Default is 200Mi.

client_oc_max_dirty(uint64, range 0 to UINT64_MAX, default 104857600)
    Sets the maximum number of dirty bytes in object cache. Default is 100Mi.

async(bool, default false)
    Enable ceph async operations (read and write).

zerocopy(bool, default false)
    Enable ceph zero copy I/O. Zero copy and client_oc are incompatible.

use_old_uuid(bool, default false)
    Use old uuid logic for ceph client. Useful when upgrading from pre 7.0
    version to latest. If this flag is set, then continue using it. As per old
    logic the uuid is formed as "ganesha-<nodeid>-<export-id>". As per new logic
    the uuid is formed as "ganesha-<64-bytes-hash>", and the hash is formed
    using nodeid, userid, fs_name and mount path. For fresh deployments of 7.0
    and later versions do not set this parameter.

register_service(bool, default false)
    Enable registration of the NFS service with the Ceph cluster.
    This allows Ceph to track the NFS service for health monitoring
    and service discovery.

nodeid(string, default "")
    Identifier used when registering this NFS instance with Ceph.
    This value must be unique per NFS node within the same Ceph cluster.
    Required only when register_service is set to true.

max_ceph_clients(uint16, range 0 to UINT16_MAX, default 0)
    Sets the maximum number of ceph clients attached to Ganesha. Default is 0.
    "0" means there is no limit on ceph clients. This may lead to failure of
    Ganesha in case resources are limited.
    This option helps administrator to control the resources being used by
    Ganesha process. Every ceph client needs certain amount of memory and number
    of threads for its working.
    When number of ceph clients attached to Ganesha exceeds the limit, Ganesha
    will stop exporting new exports which need dedicated new ceph client.

clients_per_pool(uint16, range 0 to 64, default 1)
    Sets the number of ceph clients in the pool. This is part of "ceph client
    pool" feature. In this feature, the administrator defines number of ceph
    clients which can be used to serve all exports having cmount_path as "/".
    By default for a given ceph filesystem, all exports with cmount_path "/",
    will be served by a single ceph client. For improved performance, one can
    make use of ceph client pool, and define how many ceph clients will be part
    of this pool.

CEPH_USERS {}
--------------------------------------------------------------------------------
CEPH_USERS includes one or more USERS{} blocks.

CEPH_USERS {
    USERS {
        Filesystem = <name> ;
        Userids    = user1, user2, ... ;   (comma-separated list)
        Keys       = key1,  key2,  ... ;   (comma-separated list)
    }
    USERS {..}
}

USERS {}
--------------------------------------------------------------------------------
FileSystem
    Indicates that provided users and keys in this blocks are related to this
    ceph filesystem.

Userids
    A comma separated list of ceph auth users. These users have permissions to
    work on the file system mentioned in the filed "FileSystem".

Keys
    A comma separated list of secret keys associated with above mentioned list
    of ceph auth users.


See also
==============================
:doc:`ganesha-config <ganesha-config>`\(8)
:doc:`ganesha-log-config <ganesha-log-config>`\(8)
:doc:`ganesha-core-config <ganesha-core-config>`\(8)
:doc:`ganesha-export-config <ganesha-export-config>`\(8)
:doc:`ganesha-fscrypt-config <ganesha-fscrypt-config>`\(8)

