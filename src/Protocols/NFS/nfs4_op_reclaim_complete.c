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
 * @file    nfs4_op_reclaim_complete.c
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
#include <sys/file.h>
#include "hashtable.h"
#include "log.h"
#include "fsal.h"
#include "nfs4.h"
#include "nfs_core.h"
#include "nfs_exports.h"
#include "nfs_proto_functions.h"
#include "nfs_file_handle.h"
#include "sal_data.h"
#include "sal_functions.h"

#include "gsh_lttng/gsh_lttng.h"
#if defined(USE_LTTNG) && !defined(LTTNG_PARSING)
#include "gsh_lttng/generated_traces/nfs4.h"
#endif

#ifdef USE_MACOS_QUIRKS
/**
 * @brief Whether a client's first RECLAIM_COMPLETE should not lift grace
 *
 * After a server restart macOS reconnects through nfs_connect_setup() ->
 * nfs4_create_clientid(R_SETUP), and nfs41_exchangeid(), without R_RECOVER,
 * sends RECLAIM_COMPLETE right after CREATE_SESSION, before it has
 * reclaimed anything. Counting it lets nfs_try_lift_grace() end grace
 * within seconds, once every client in the recovery records has sent one;
 * the reclaims nfs_recover() sends later then get NFS4ERR_NO_GRACE. A
 * failed reclaim leaves macOS's node holding the dead delegation
 * (nfs4_open_reclaim_rpc() never clears N_DELEG_*), and nfs_get_stateid()
 * keeps sending its stateid on READ, so the mount loops through recovery
 * forever. nfs_recover() ends by sending another RECLAIM_COMPLETE, which
 * we count instead. If the client never runs recovery, grace lasts its
 * full duration.
 *
 * @todo Remove once macOS is fixed.
 *
 * @return true to leave the client's RECLAIM_COMPLETE uncounted.
 */
static bool early_reclaim_complete_quirk(void)
{
	return macos_quirk_applies(
		nfs_param.nfsv4_param.macos_quirk_late_reclaim);
}
#endif

/**
 *
 * @brief The NFS4_OP_RECLAIM_COMPLETE4 operation.
 *
 * This function implements the NFS4_OP_RECLAIM_COMPLETE4 operation.
 *
 * @param[in]     op    Arguments for the nfs4_op
 * @param[in,out] data  Compound request's data
 * @param[out]    resp  Results for the nfs4_op
 *
 * @return per RFC5661 p. 372
 *
 * @see nfs4_Compound
 *
 */

enum nfs_req_result nfs4_op_reclaim_complete(struct nfs_argop4 *op,
					     compound_data_t *data,
					     struct nfs_resop4 *resp)
{
	RECLAIM_COMPLETE4args *const arg_RECLAIM_COMPLETE4 =
		&op->nfs_argop4_u.opreclaim_complete;
	RECLAIM_COMPLETE4res *const res_RECLAIM_COMPLETE4 =
		&resp->nfs_resop4_u.opreclaim_complete;
	nfs_client_id_t *clientid = data->session->clientid_record;

	GSH_AUTO_TRACEPOINT(nfs4, op_reclaim_complete_start, TRACE_INFO,
			    "RECLAIM COMPLETE args: rca_one_fs={}",
			    arg_RECLAIM_COMPLETE4->rca_one_fs);

	resp->resop = NFS4_OP_RECLAIM_COMPLETE;

	res_RECLAIM_COMPLETE4->rcr_status = NFS4_OK;

#ifdef USE_MACOS_QUIRKS
	/* The RECLAIM_COMPLETE macOS sends when nfs_recover() is done; count
	 * it now (see early_reclaim_complete_quirk()).
	 */
	if (clientid->cid_reclaim_complete_uncounted &&
	    !arg_RECLAIM_COMPLETE4->rca_one_fs) {
		clientid->cid_reclaim_complete_uncounted = false;
		atomic_inc_int32_t(&reclaim_completes);
		LogInfo(COMPONENT_CLIENTID,
			"Counting the second RECLAIM_COMPLETE toward lifting grace (macOS_quirk_late_reclaim)");
		nfs_try_lift_grace();
		goto out;
	}
#endif

	/* For now, we don't handle rca_one_fs, so we won't complain about
	 * complete already for it.
	 */
	if (clientid->cid_cb.v41.cid_reclaim_complete &&
	    !arg_RECLAIM_COMPLETE4->rca_one_fs) {
		res_RECLAIM_COMPLETE4->rcr_status = NFS4ERR_COMPLETE_ALREADY;
		return NFS_REQ_ERROR;
	}

	if (!arg_RECLAIM_COMPLETE4->rca_one_fs) {
		clientid->cid_cb.v41.cid_reclaim_complete = true;
#ifdef USE_MACOS_QUIRKS
		if (clientid->cid_allow_reclaim &&
		    early_reclaim_complete_quirk()) {
			clientid->cid_reclaim_complete_uncounted = true;
			LogInfo(COMPONENT_CLIENTID,
				"Not counting a RECLAIM_COMPLETE sent before reclaiming toward lifting grace (macOS_quirk_late_reclaim)");
		} else
#endif
			if (clientid->cid_allow_reclaim)
				atomic_inc_int32_t(&reclaim_completes);
		nfs41_reclaim_complete_clid(clientid);
	}

#ifdef USE_MACOS_QUIRKS
out:
#endif

	GSH_AUTO_TRACEPOINT(nfs4, op_reclaim_complete_end, TRACE_INFO,
			    "RECLAIM COMPLETE rs: status={}",
			    res_RECLAIM_COMPLETE4->rcr_status);
	return NFS_REQ_OK;
} /* nfs41_op_reclaim_complete */

/**
 * @brief Free memory allocated for RECLAIM_COMPLETE result
 *
 * This function frees anty memory allocated for the result of the
 * NFS4_OP_RECLAIM_COMPLETE operation.
 */
void nfs4_op_reclaim_complete_Free(nfs_resop4 *resp)
{
	/* Nothing to be done */
}
