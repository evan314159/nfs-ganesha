// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
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
 *
 * ---------------------------------------
 */

/**
 * @file    nfs4_op_openattr.c
 * @brief   Routines used for managing the NFS4 COMPOUND functions.
 */

#include "config.h"
#include "hashtable.h"
#include "log.h"
#include "nfs4.h"
#include "nfs_core.h"
#include "nfs_exports.h"
#include "nfs_proto_functions.h"
#include "nfs_proto_tools.h"
#include "nfs_file_handle.h"
#include "nfs_convert.h"

/**
 *
 * @brief NFS4_OP_OPENATTR
 *
 * This function implements the NFS4_OP_OPENATTR operation: the current
 * filehandle becomes that of the object's named attribute directory.
 *
 * @param[in]     op   Arguments for nfs4_op
 * @param[in,out] data Compound request's data
 * @param[out]    resp Results for nfs4_op
 *
 * @return per RFC5661, pp. 370-1
 *
 */
enum nfs_req_result nfs4_op_openattr(struct nfs_argop4 *op,
				     compound_data_t *data,
				     struct nfs_resop4 *resp)
{
	OPENATTR4args *const arg_OPENATTR4 = &op->nfs_argop4_u.opopenattr;
	OPENATTR4res *const res_OPENATTR4 = &resp->nfs_resop4_u.opopenattr;
	struct fsal_obj_handle *obj = data->current_obj;
	struct fsal_obj_handle *attrdir = NULL;
	const fsal_accessflags_t read_access =
		FSAL_MODE_MASK_SET(FSAL_R_OK) |
		FSAL_ACE4_MASK_SET(FSAL_ACE_PERM_READ_NAMED_ATTR);
	const fsal_accessflags_t write_access =
		FSAL_MODE_MASK_SET(FSAL_W_OK) |
		FSAL_ACE4_MASK_SET(FSAL_ACE_PERM_WRITE_NAMED_ATTR);
	object_file_type_t type;
	fsal_status_t status;

	resp->resop = NFS4_OP_OPENATTR;

	res_OPENATTR4->status = nfs4_sanity_check_FH(data, NO_FILE_TYPE, false);

	if (res_OPENATTR4->status != NFS4_OK)
		return NFS_REQ_ERROR;

	/* Named attributes and their directories can't have named attributes:
	 * RFC 8881 18.17.3 requires NFS4ERR_WRONG_TYPE.
	 */
	type = nfs4_object_type(obj);

	if (type == EXTENDED_ATTR || type == ATTR_DIRECTORY) {
		res_OPENATTR4->status = NFS4ERR_WRONG_TYPE;
		return NFS_REQ_ERROR;
	}

	/* Opening the directory needs ACE4_READ_NAMED_ATTRS, and creating it
	 * ACE4_WRITE_NAMED_ATTRS too (RFC 8881 6.2.1.3.1).
	 */
	status = fsal_access(obj, read_access);

	if (!FSAL_IS_ERROR(status))
		status = obj->obj_ops->openattr(obj, false, &attrdir, NULL);

	if (status.major == ERR_FSAL_NOENT && arg_OPENATTR4->createdir) {
		/* Creating the directory needs a writable export */
		if ((op_ctx->export_perms.options &
		     EXPORT_OPTION_MD_WRITE_ACCESS) == 0) {
			res_OPENATTR4->status = NFS4ERR_ROFS;
			return NFS_REQ_ERROR;
		}

		status = fsal_access(obj, write_access);

		if (!FSAL_IS_ERROR(status))
			status = obj->obj_ops->openattr(obj, true, &attrdir,
							NULL);
	}

	if (FSAL_IS_ERROR(status)) {
		res_OPENATTR4->status = nfs4_Errno_status(status);
		return NFS_REQ_ERROR;
	}

	if (!nfs4_FSALToFhandle(false, &data->currentFH, attrdir,
				op_ctx->ctx_export)) {
		attrdir->obj_ops->put_ref(attrdir);
		res_OPENATTR4->status = NFS4ERR_SERVERFAULT;
		return NFS_REQ_ERROR;
	}

	/* Keep the pointer within the compound data */
	set_current_entry(data, attrdir);

	/* Put our ref */
	attrdir->obj_ops->put_ref(attrdir);

	res_OPENATTR4->status = NFS4_OK;

	return NFS_REQ_OK;
} /* nfs4_op_openattr */

/**
 * @brief Free memory allocated for OPENATTR result
 *
 * This function frees any memory allocated for the result of the
 * NFS4_OP_OPENATTR operation.
 *
 * @param[in,out] resp nfs4_op results
 */
void nfs4_op_openattr_Free(nfs_resop4 *resp)
{
	/* Nothing to be done */
}
