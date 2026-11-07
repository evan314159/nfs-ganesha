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
 * @file    nfs4_op_delegreturn.c
 * @brief   Routines used for managing the NFS4 COMPOUND functions.
 *
 * Routines used for managing the NFS4 COMPOUND functions.
 *
 *
 */
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include "hashtable.h"
#include "log.h"
#include "nfs4.h"
#include "nfs_core.h"
#include "nfs_convert.h"
#include "nfs_exports.h"
#include "nfs_file_handle.h"
#include "nfs_proto_functions.h"
#include "sal_functions.h"

#ifdef USE_MACOS_QUIRKS
/**
 * @brief Whether to answer NFS4_OK to a DELEGRETURN whose stateid failed its
 *        check because it belongs to an earlier client ID
 *
 * When macOS's state is lost (a server restart, or a lease expiry or
 * revoke followed by a new client ID), its recovery establishes a new
 * client ID and then, in nfs4_expired_check_delegation(), returns each
 * delegation it still thinks it holds. It sends that DELEGRETURN without
 * R_RECOVER, so the NFS4ERR_BAD_STATEID we answer for a stateid of the
 * earlier client ID makes nfs41_request_error_should_restart() wait for
 * recovery, in the recovery thread itself, and the mount hangs. The
 * delegation went away with that client ID (or with the earlier server
 * instance), so with macOS_quirk_return_stale_delegation we answer NFS4_OK.
 * Linux knfsd also answers NFS4ERR_BAD_STATEID here (it answers NFS4_OK only
 * for a delegation it revoked and still tracks), so this departs from both.
 *
 * @todo Remove once macOS is fixed.
 *
 * @param[in] data     Compound data
 * @param[in] stateid  The delegation stateid being returned
 * @param[in] status   What the stateid check returned
 *
 * @return true to answer NFS4_OK instead.
 */
static bool return_stale_delegation_quirk(compound_data_t *data,
					  const stateid4 *stateid,
					  nfsstat4 status)
{
	clientid4 clientid;
	uint32_t epoch;

	if (data->minorversion == 0 || data->session == NULL)
		return false;

	if (status != NFS4ERR_BAD_STATEID && status != NFS4ERR_STALE_STATEID &&
	    status != NFS4ERR_EXPIRED)
		return false;

	memcpy(&clientid, stateid->other, sizeof(clientid));
	epoch = clientid >> (clientid4)32;

	/* Leave the special stateids (all zeros, all ones) alone. */
	if (epoch == 0 || epoch == UINT32_MAX)
		return false;

	if (clientid == data->session->clientid)
		return false;

	return macos_quirk_applies(
		nfs_param.nfsv4_param.macos_quirk_return_stale_delegation);
}
#endif

/**
 * @brief NFS4_OP_DELEGRETURN
 *
 * This function implements the NFS4_OP_DELEGRETURN operation.
 *
 * @param[in]     op   Arguments for nfs4_op
 * @param[in,out] data Compound request's data
 * @param[out]    resp Results for nfs4_op
 *
 * @return per RFC 5661, p. 364
 */
enum nfs_req_result nfs4_op_delegreturn(struct nfs_argop4 *op,
					compound_data_t *data,
					struct nfs_resop4 *resp)
{
	DELEGRETURN4args *const arg_DELEGRETURN4 =
		&op->nfs_argop4_u.opdelegreturn;
	DELEGRETURN4res *const res_DELEGRETURN4 =
		&resp->nfs_resop4_u.opdelegreturn;

	state_status_t state_status;
	state_t *state_found;
	const char *tag = "DELEGRETURN";
	state_owner_t *owner;

	LogDebug(
		COMPONENT_STATE,
		"Entering NFS v4 DELEGRETURN handler -----------------------------------------------------");

	/* Initialize to sane default */
	resp->resop = NFS4_OP_DELEGRETURN;

	/* If the filehandle is invalid. Delegations are only supported on
	 * regular files at the moment.
	 */
	res_DELEGRETURN4->status =
		nfs4_sanity_check_FH(data, REGULAR_FILE, false);

	if (res_DELEGRETURN4->status != NFS4_OK) {
		if (res_DELEGRETURN4->status == NFS4ERR_ISDIR)
			res_DELEGRETURN4->status = NFS4ERR_INVAL;
		return NFS_REQ_ERROR;
	}

	/* Check stateid correctness and get pointer to state */
	res_DELEGRETURN4->status =
		nfs4_Check_Stateid(&arg_DELEGRETURN4->deleg_stateid,
				   data->current_obj, &state_found, data,
				   STATEID_SPECIAL_FOR_LOCK, 0, false, tag);

#ifdef USE_MACOS_QUIRKS
	if (res_DELEGRETURN4->status != NFS4_OK &&
	    return_stale_delegation_quirk(data,
					  &arg_DELEGRETURN4->deleg_stateid,
					  res_DELEGRETURN4->status)) {
		LogInfo(COMPONENT_STATE,
			"DELEGRETURN of a delegation of an earlier client ID got %s, answering NFS4_OK",
			nfsstat4_to_str(res_DELEGRETURN4->status));
		res_DELEGRETURN4->status = NFS4_OK;
		return NFS_REQ_OK;
	}
#endif

	if (res_DELEGRETURN4->status != NFS4_OK)
		return NFS_REQ_ERROR;

	if (state_found->state_type != STATE_TYPE_DELEG) {
		res_DELEGRETURN4->status = NFS4ERR_BAD_STATEID;
		goto out_unlock;
	}

	owner = get_state_owner_ref(state_found);

	if (owner == NULL) {
		/* Something has gone stale. */
		LogDebug(COMPONENT_STATE, "Stale state");
		res_DELEGRETURN4->status = NFS4ERR_STALE;
		goto out_unlock;
	}

	STATELOCK_lock(data->current_obj);

	deleg_heuristics_recall(data->current_obj, owner, state_found);
	reset_cbgetattr_stats(data->current_obj);

	/* Release reference taken above. */
	dec_state_owner_ref(owner);

	/* Now we have a lock owner and a stateid.
	 * Go ahead and push unlock into SAL (and FSAL) to return
	 * the delegation.
	 */
	state_status = release_lease_lock(data->current_obj, state_found);

	res_DELEGRETURN4->status = nfs4_Errno_state(state_status);

	if (state_status == STATE_SUCCESS) {
		/* Successful exit */
		LogDebug(COMPONENT_STATE, "Successful exit");

		state_del_locked(state_found);
	}
	STATELOCK_unlock(data->current_obj);

out_unlock:

	dec_state_t_ref(state_found);

	return nfsstat4_to_nfs_req_result(res_DELEGRETURN4->status);
} /* nfs4_op_delegreturn */

/**
 * @brief Free memory allocated for DELEGRETURN result
 *
 * This function frees any memory allocated for the result of the
 * DELEGRETURN operation.
 *
 * @param resp  [INOUT]    Pointer to nfs4_op results
 */
void nfs4_op_delegreturn_Free(nfs_resop4 *resp)
{
	/* Nothing to be done */
}
