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
#define MOD_TBL_SIZE		"\x0A""table-size"	// table
#define MOD_WHITELIST		"\x09""whitelist"

const yp_item_t dnsrtt_conf[] = {
	{ MOD_RATE_LIMIT, YP_TINT, YP_VINT = { 1, INT32_MAX } },
	{ MOD_SLIP,       YP_TINT, YP_VINT = { 0, 100, 1 } },
	{ MOD_TBL_SIZE,   YP_TINT, YP_VINT = { 1, INT64_MAX, 393241 } },
	{ MOD_WHITELIST,  YP_TNET, YP_VNONE, YP_FMULTI },
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
	dnsrtt_table_t *dnsrtt;
	//dnsrtt_stat_t *stat;
	int slip;
	knotd_conf_t whitelist;
} dnsrtt_ctx_t;

static const knot_dname_t *name_from_rrsig(const knot_rrset_t *rr)
{
	if (rr == NULL) {
		return NULL;
	}
	if (rr->type != KNOT_RRTYPE_RRSIG) {
		return NULL;
	}

	// This is a signature.
	return knot_rrsig_signer_name(rr->rrs.rdata);
}

static const knot_dname_t *name_from_authrr(const knot_rrset_t *rr)
{
	if (rr == NULL) {
		return NULL;
	}
	if (rr->type != KNOT_RRTYPE_NS && rr->type != KNOT_RRTYPE_SOA) {
		return NULL;
	}

	// This is a valid authority RR.
	return rr->owner;
}

static knotd_state_t ratelimit_apply(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);
	// knotd_mod_log(mod, LOG_DEBUG, "   ========= APPLYING DNS-RTT... =========   ");

	dnsrtt_ctx_t *ctx = knotd_mod_ctx(mod);
	
	// check whether a query is TCP or not
	bool tcp = false;
	if (!(qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE)) {
		tcp = true;
	}

	// DNSRTT is not applied to responses with a valid cookie.
	if (qdata->params->flags & KNOTD_QUERY_FLAG_COOKIE) {
		return state;
	}

	// Exempt clients.
	if (knotd_conf_addr_range_match(&ctx->whitelist, qdata->params->remote)) {
		return state;
	}	

	// knotd_mod_log(mod, LOG_DEBUG, "Query flags: %d", qdata->params->flags);

	dnsrtt_req_t req = {
		.wire = pkt->wire,
		.query = qdata->query,
		tcp = tcp
	};

	if (!EMPTY_LIST(qdata->extra->wildcards)) {
		req.flags = dnsrtt_REQ_WILDCARD;
	}

	// Take the zone name if known.
	const knot_dname_t *zone_name = knotd_qdata_zone_name(qdata);

	// Take the signer name as zone name if there is an RRSIG.
	if (zone_name == NULL) {
		const knot_pktsection_t *ans = knot_pkt_section(pkt, KNOT_ANSWER);
		for (int i = 0; i < ans->count; i++) {
			zone_name = name_from_rrsig(knot_pkt_rr(ans, i));
			if (zone_name != NULL) {
				break;
			}
		}
	}

	// Take the NS or SOA owner name if there is no RRSIG.
	if (zone_name == NULL) {
		const knot_pktsection_t *auth = knot_pkt_section(pkt, KNOT_AUTHORITY);
		for (int i = 0; i < auth->count; i++) {
			zone_name = name_from_authrr(knot_pkt_rr(auth, i));
			if (zone_name != NULL) {
				break;
			}
		}
	}

	int ret = dnsrtt_query(ctx->dnsrtt, ctx->slip, qdata->params->remote, &req, zone_name, mod);
	if (ret == KNOT_EOK) {
		// DNSRTT not applied.
		return state;
	}

	if (ret == KNOT_ELIMIT) {
		// Slip the answer (truncated).
		qdata->err_truncated = true;
		return KNOTD_STATE_FAIL;
	} else {
		// Drop the answer.
		return KNOTD_STATE_NOOP;
	}
}

static void dnsrtt_ctx_free(dnsrtt_ctx_t *ctx)
{
	assert(ctx);

	dnsrtt_destroy(ctx->dnsrtt);
	free(ctx);
}

int dnsrtt_load(knotd_mod_t *mod)
{	
	// loading DNSRTT
	knotd_mod_log(mod, LOG_DEBUG, "   ========= Loading DNSRTT... =========   ");
	
	// Create DNSRTT context.
	dnsrtt_ctx_t *ctx = calloc(1, sizeof(dnsrtt_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Create table
	uint32_t rate = knotd_conf_mod(mod, MOD_RATE_LIMIT).single.integer;
	size_t size = knotd_conf_mod(mod, MOD_TBL_SIZE).single.integer;
	ctx->dnsrtt = dnsrtt_create(size, rate);
	if (ctx->dnsrtt == NULL) {
		dnsrtt_ctx_free(ctx);
		return KNOT_ENOMEM;
	}

	// Get slip.
	ctx->slip = knotd_conf_mod(mod, MOD_SLIP).single.integer;

	// Get whitelist.
	ctx->whitelist = knotd_conf_mod(mod, MOD_WHITELIST);

	knotd_mod_ctx_set(mod, ctx);
	knotd_mod_log(mod, LOG_DEBUG, "   ========= Loading complete: rate=%lld, table-size=%ld, slip=%ld =========   ", 
				      ctx->dnsrtt->rate, ctx->dnsrtt->size, ctx->slip);
	return knotd_mod_hook(mod, KNOTD_STAGE_END, ratelimit_apply);
}

void dnsrtt_unload(knotd_mod_t *mod)
{
	dnsrtt_ctx_t *ctx = knotd_mod_ctx(mod);

	dnsrtt_ctx_free(ctx);
}

KNOTD_MOD_API(dnsrtt, KNOTD_MOD_FLAG_SCOPE_ANY,
              dnsrtt_load, dnsrtt_unload, dnsrtt_conf, dnsrtt_conf_check);
