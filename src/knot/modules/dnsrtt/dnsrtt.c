/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "knot/include/module.h"
#include "knot/nameserver/process_query.h" // Dependency on qdata->extra!
#include "knot/modules/dnsrtt/functions.h"

#define MOD_RATE_LIMIT		"\x0A""rate-limit"	// how many tcp do we want
#define MOD_SLIP		"\x04""slip"		// the probablity of truncated response
#define MOD_TBL_SIZE		"\x0A""table-size"

const yp_item_t dnsrtt_conf[] = {
	{ MOD_RATE_LIMIT, YP_TINT, YP_VINT = { 1, INT32_MAX } },
	{ MOD_SLIP,       YP_TINT, YP_VINT = { 0, 100, 1 } },
	{ MOD_TBL_SIZE,   YP_TINT, YP_VINT = { 1, INT64_MAX, 393241 } },
	{ NULL }
};

int dnsrtt_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t limit = knotd_conf_check_item(args, MOD_RATE_LIMIT);
	if (limit.count == 0) {
		args->err_str = "no rate limit specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

typedef struct {
	dnsrtt_pref_table_t *dnsrtt;
	int slip;
} dnsrtt_pref_ctx_t;

static knotd_state_t ratelimit_apply(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);
	knotd_mod_log(mod, LOG_DEBUG, "APPLYING DNS-RTT...");

	dnsrtt_pref_ctx_t *pref_ctx = knotd_mod_ctx(mod);
	
	// check whether a query is TCP or not
	bool tcp = false;
	if (!(qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE)) {
		tcp = true;
	}	

	// knotd_mod_log(mod, LOG_DEBUG, "Query flags: %d", qdata->params->flags);

	dnsrtt_req_t req = {
		.wire = pkt->wire,
		.query = qdata->query,
		tcp = tcp
	};

	int ret = dnsrtt_pref_query(pref_ctx->dnsrtt, pref_ctx->slip, qdata->params->remote, &req, mod);
	if (ret == KNOT_EOK) {
		// Rate limiting not applied.
		return state;
	}

	if (ret == KNOT_ELIMIT) {
		// Slip the answer (truncated).
		knotd_mod_stats_incr(mod, qdata->params->thread_id, 0, 0, 1);
		qdata->err_truncated = true;
		return KNOTD_STATE_FAIL;
	} else {
		// Drop the answer.
		knotd_mod_stats_incr(mod, qdata->params->thread_id, 1, 0, 1);
		return KNOTD_STATE_NOOP;
	}
}

static void pref_ctx_free(dnsrtt_pref_ctx_t *pref_ctx)
{
	assert(pref_ctx);

	dnsrtt_pref_destroy(pref_ctx->dnsrtt);
	free(pref_ctx);
}

int dnsrtt_load(knotd_mod_t *mod)
{	
	// loading DNS-RTT
	knotd_mod_log(mod, LOG_DEBUG, "Loading DNS-RTT...");
	
	// Create dnsrtt context.
	dnsrtt_pref_ctx_t *pref_ctx = calloc(1, sizeof(dnsrtt_pref_ctx_t));

	if (pref_ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Create table.
	uint32_t rate = knotd_conf_mod(mod, MOD_RATE_LIMIT).single.integer;
	size_t size = knotd_conf_mod(mod, MOD_TBL_SIZE).single.integer;
	pref_ctx->dnsrtt = dnsrtt_pref_create(size, rate);
	if (pref_ctx->dnsrtt == NULL) {
		pref_ctx_free(pref_ctx);
		return KNOT_ENOMEM;
	}

	// Get slip.
	pref_ctx->slip = knotd_conf_mod(mod, MOD_SLIP).single.integer;

	// Set up statistics counters.
	int ret = knotd_mod_stats_add(mod, "slipped", 1, NULL);
	if (ret != KNOT_EOK) {
		pref_ctx_free(pref_ctx);
		return ret;
	}

	ret = knotd_mod_stats_add(mod, "dropped", 1, NULL);
	if (ret != KNOT_EOK) {
		pref_ctx_free(pref_ctx);
		return ret;
	}

	knotd_mod_ctx_set(mod, pref_ctx);
	knotd_mod_log(mod, LOG_DEBUG, "Loading complete: rate=%lld, table-size=%ld, slip=%ld", 
				      pref_ctx->dnsrtt->rate, pref_ctx->dnsrtt->size, pref_ctx->slip);
	return knotd_mod_hook(mod, KNOTD_STAGE_END, ratelimit_apply);
}

void dnsrtt_unload(knotd_mod_t *mod)
{
	dnsrtt_pref_ctx_t *pref_ctx = knotd_mod_ctx(mod);

	pref_ctx_free(pref_ctx);
}

KNOTD_MOD_API(dnsrtt, KNOTD_MOD_FLAG_SCOPE_ANY,
              dnsrtt_load, dnsrtt_unload, dnsrtt_conf, dnsrtt_conf_check);
