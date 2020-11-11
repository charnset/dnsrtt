/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <assert.h>
#include <time.h>

#include "knot/modules/dnsrtt/functions.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"

/* Hopscotch defines. */
// #define HOP_LEN (sizeof(unsigned)*8)
/* Limits (class, ipv6 remote, dname) */
// #define dnsrtt_CLSBLK_MAXLEN (1 + 8 + 255)
/* CIDR block prefix lengths for v4/v6 */
#define dnsrtt_V4_PREFIX_LEN 3 /* /24 */
#define dnsrtt_V6_PREFIX_LEN 7 /* /56 */
/* Defaults */
// #define dnsrtt_SSTART 2 /* 1/Nth of the rate for slow start */
// #define dnsrtt_PSIZE_LARGE 1024
// #define dnsrtt_CAPACITY 4 /* Window size in seconds */
#define dnsrtt_LOCK_GRANULARITY 32 /* Last digit granularity */
#define dnsrtt_INTERVAL 3600 /* Interval size in seconds */

static void subnet_tostr(char *dst, size_t maxlen, const struct sockaddr_storage *ss)
{
	const void *addr;
	const char *suffix;

	if (ss->ss_family == AF_INET6) {
		addr = &((struct sockaddr_in6 *)ss)->sin6_addr;
		suffix = "/56";
	} else {
		addr = &((struct sockaddr_in *)ss)->sin_addr;
		suffix = "/24";
	}

	if (inet_ntop(ss->ss_family, addr, dst, maxlen) != NULL) {
		strlcat(dst, suffix, maxlen);
	} else {
		dst[0] = '\0';
	}
}

static void dnsrtt_lock(dnsrtt_pref_table_t *pref_tbl, int lk_id)
{
	assert(lk_id > -1);
	pthread_mutex_lock(pref_tbl->lk + lk_id);
}

static void dnsrtt_unlock(dnsrtt_pref_table_t *pref_tbl, int lk_id)
{
	assert(lk_id > -1);
	pthread_mutex_unlock(pref_tbl->lk + lk_id);
}

static void dnsrtt_pref_stat_clear(dnsrtt_pref_stat_t *stat, uint32_t ts)
{
	stat->start = ts;
	stat->n_query = 0;
	stat->n_pref = 0;
	stat->n_tcp = 0;
	stat->n_pref_valid = 0;
	stat->n_tcbit = 0;
	stat->n_tcbit_pref = 0;
	stat->n_tcbit_pref_valid = 0;
}

static int dnsrtt_pref_stat_setlocks(dnsrtt_pref_stat_t *pref_stat)
{
	if (pthread_mutex_init(&pref_stat->ll_str, NULL) < 0) {
		return KNOT_ENOMEM;
	}
	if (pthread_mutex_init(&pref_stat->ll_nq, NULL) < 0) {
		return KNOT_ENOMEM;
	}
	if (pthread_mutex_init(&pref_stat->ll_nprf, NULL) < 0) {
		return KNOT_ENOMEM;
	}
	if (pthread_mutex_init(&pref_stat->ll_ntcp, NULL) < 0) {
		return KNOT_ENOMEM;
	}
	if (pthread_mutex_init(&pref_stat->ll_nprf_v, NULL) < 0) {
		return KNOT_ENOMEM;
	}
	if (pthread_mutex_init(&pref_stat->ll_ntcbit, NULL) < 0) {
		return KNOT_ENOMEM;
	}
	if (pthread_mutex_init(&pref_stat->ll_ntcbit_prf, NULL) < 0) {
		return KNOT_ENOMEM;
	}
	if (pthread_mutex_init(&pref_stat->ll_ntcbit_pref_v, NULL) < 0) {
		return KNOT_ENOMEM;
	}
	return KNOT_EOK;
}

dnsrtt_pref_stat_t *dnsrtt_pref_stat_create(void)
{
	//knotd_mod_log(mod, LOG_DEBUG, "1.5");
	const size_t pref_stat_len = sizeof(dnsrtt_pref_stat_t);
	dnsrtt_pref_stat_t *pref_stat = calloc(1, pref_stat_len);
	//knotd_mod_log(mod, LOG_DEBUG, "1.6");
	if (!pref_stat) {
		return NULL;
	}

	dnsrtt_pref_stat_clear(pref_stat, time_now().tv_sec);
	//knotd_mod_log(mod, LOG_DEBUG, "1.7");

	if (dnsrtt_pref_stat_setlocks(pref_stat) != KNOT_EOK) {
		free(pref_stat);
		return NULL;
	}
	//knotd_mod_log(mod, LOG_DEBUG, "1.8");

	return pref_stat;
}

static int dnsrtt_pref_table_setlocks(dnsrtt_pref_table_t *pref_tbl, uint32_t granularity)
{
	assert(!pref_tbl->lk); /* Cannot change while locks are used. */
	assert(granularity <= pref_tbl->size / 10); /* Due to int. division err. */

	if (pthread_mutex_init(&pref_tbl->ll, NULL) < 0) {
		return KNOT_ENOMEM;
	}

	/* Alloc new locks. */
	pref_tbl->lk = malloc(granularity * sizeof(pthread_mutex_t));
	if (!pref_tbl->lk) {
		return KNOT_ENOMEM;
	}
	memset(pref_tbl->lk, 0, granularity * sizeof(pthread_mutex_t));

	/* Initialize. */
	for (size_t i = 0; i < granularity; ++i) {
		if (pthread_mutex_init(pref_tbl->lk + i, NULL) < 0) {
			break;
		}
		++pref_tbl->lk_count;
	}

	/* Incomplete initialization */
	if (pref_tbl->lk_count != granularity) {
		for (size_t i = 0; i < pref_tbl->lk_count; ++i) {
			pthread_mutex_destroy(pref_tbl->lk + i);
		}
		free(pref_tbl->lk);
		pref_tbl->lk_count = 0;
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

dnsrtt_pref_table_t *dnsrtt_pref_table_create(size_t size, uint32_t rate)
{
	if (size == 0) {
		return NULL;
	}

	const size_t pref_tbl_len = sizeof(dnsrtt_pref_table_t) + size * sizeof(dnsrtt_pref_item_t);
	dnsrtt_pref_table_t *pref_tbl = calloc(1, pref_tbl_len);
	if (!pref_tbl) {
		return NULL;
	}
	pref_tbl->size = size;
	pref_tbl->rate = rate;

	if (dnsrtt_pref_table_setlocks(pref_tbl, dnsrtt_LOCK_GRANULARITY) != KNOT_EOK) {
		free(pref_tbl);
		return NULL;
	}

	return pref_tbl;
}

/*!
 * \brief Roll a dice whether answer slips or not.
 * \param n_slip Number represents every Nth answer that is slipped.
 * \return true or false
 */
bool dnsrtt_slip_roll(int n_slip)
{
	switch (n_slip) {
	case 0:
		return false;
	case 1:
		return true;
	default:
		return (dnssec_random_uint16_t() % n_slip == 0);
	}
}

static void dnsrtt_pref_stat_update(dnsrtt_pref_stat_t *stat, bool tcp, bool pref_valid, bool tcbit, bool tcbit_pref, bool tcbit_pref_valid)
{
	// lock to update stat
	// tcp: tcp query?
	// pref_valid: ntcp == rate (w/o TC bit help)?
	// tcbit: TC bit reply?
	// tcbit_pref: first TC bit reply for that prefix?
	// tcbit_pref_valid: ntcbit == rate?
	if (tcp) {
		pthread_mutex_lock(&stat->ll_ntcp);
		++stat->n_tcp;
		pthread_mutex_unlock(&stat->ll_ntcp);
	}
	if (pref_valid) {
		pthread_mutex_lock(&stat->ll_nprf_v);
		++stat->n_pref_valid;
		pthread_mutex_unlock(&stat->ll_nprf_v);
	}
	if (tcbit) {
		pthread_mutex_lock(&stat->ll_ntcbit);
		++stat->n_tcbit;
		pthread_mutex_unlock(&stat->ll_ntcbit);
	}
	if (tcbit_pref) {
		pthread_mutex_lock(&stat->ll_ntcbit_prf);
		++stat->n_tcbit_pref;
		pthread_mutex_unlock(&stat->ll_ntcbit_prf);
	}
	if (tcbit_pref_valid) {
		pthread_mutex_lock(&stat->ll_ntcbit_pref_v);
		++stat->n_tcbit_pref_valid;
		pthread_mutex_unlock(&stat->ll_ntcbit_pref_v);
	}
}

static dnsrtt_pref_item_t *dnsrtt_pref_id(dnsrtt_pref_table_t *tbl, const struct sockaddr_storage *remote,
					   dnsrtt_req_t *req, uint32_t stamp, int *lock, knotd_mod_t *mod)
{
	uint64_t netblk = 0;
	if (remote->ss_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)remote;
		memcpy(&netblk, &ipv6->sin6_addr, dnsrtt_V6_PREFIX_LEN);
	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)remote;
		memcpy(&netblk, &ipv4->sin_addr, dnsrtt_V4_PREFIX_LEN);
	}
	
	// find id
	uint64_t id = netblk % tbl->size;
	// knotd_mod_log(mod, LOG_DEBUG, "pref (in network byteorder, adjust masks) %lld : id %lld", (long long)netblk, (long long)id);

	// Lock for lookup
	pthread_mutex_lock(&tbl->ll);

	// Assign granular lock and unlock lookup
	*lock = id % tbl->lk_count;
	dnsrtt_lock(tbl, *lock);
	pthread_mutex_unlock(&tbl->ll);

	// Find bucket 
	dnsrtt_pref_item_t *bucket = &tbl->arr[id];

	// Check whether bucket is empty or not
	if (!bucket->netblk) {
		// knotd_mod_log(mod, LOG_DEBUG, "Initiating an empty bucket...");
		bucket->netblk = netblk;
		bucket->nquery = 0;
		bucket->ntcp = 0;
		bucket->time = stamp;
		bucket->tcbit = 0;
	}

	return bucket;
}


int dnsrtt_pref_query(dnsrtt_pref_table_t *dnsrtt, dnsrtt_pref_stat_t *stat, int slip, const struct sockaddr_storage *remote, dnsrtt_req_t *req, knotd_mod_t *mod)
{	
	if (!dnsrtt || !req || !remote) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	//  Fetch bucket
	int lock = -1;
	uint32_t now = time_now().tv_sec;
	dnsrtt_pref_item_t *bucket = dnsrtt_pref_id(dnsrtt, remote, req, now, &lock, mod);
	
	if (!bucket) {
		if (lock > -1) {
			dnsrtt_unlock(dnsrtt, lock);
		}
		return KNOT_ERROR;
	}

	// Visit bucket
	// knotd_mod_log(mod, LOG_DEBUG, "Visiting a bucket...");
	char addr_str[SOCKADDR_STRLEN];
	subnet_tostr(addr_str, sizeof(addr_str), remote);
	// knotd_mod_log(mod, LOG_DEBUG, "IP %s, pref %lld, ntcp %lld, lastseen %lld", addr_str, (long long)bucket->netblk, (long long)bucket->ntcp, (long long)bucket->time);
	

	// Fetch start and update n_query (interval) 
	pthread_mutex_lock(&stat->ll_str);
	uint32_t start = stat->start;
	pthread_mutex_unlock(&stat->ll_str);

	pthread_mutex_lock(&stat->ll_nq);
	stat->n_query += 1;
	pthread_mutex_unlock(&stat->ll_nq);

	// New interval or not?, if so refresh bucket
	if (bucket->time < start) {
		knotd_mod_log(mod, LOG_INFO, "BUCKET,%s,%lld,%lld,%lld,%lld", addr_str, (long long)bucket->nquery, (long long)bucket->ntcp, 
					(long long)bucket->tcbit, (long long)start);
		bucket->nquery = 0;
		bucket->ntcp = 0;
		bucket->time = now;
		bucket->tcbit = 0;
	}

	// Update bucket (number of queries, time)
	++bucket->nquery;
	if (bucket->nquery == 1) {
		pthread_mutex_lock(&stat->ll_nprf);
		++stat->n_pref;
		pthread_mutex_unlock(&stat->ll_nprf);
	}
	bucket->time = now;	

	if (req->tcp) {	// TCP queries
		// knotd_mod_log(mod, LOG_DEBUG, "(TCP) IP %s, pref %lld, ntcp %lld, lastseen %lld", 
						//addr_str, (long long)bucket->netblk, (long long)bucket->ntcp, (long long)bucket->time);
		++bucket->ntcp; // update bucket ntcp (increasing)
		// bucket->time = now; // update lastseen
		if (bucket->ntcp == dnsrtt->rate) {
			dnsrtt_pref_stat_update(stat, 1, 1, 0, 0, 0);
		} else {
			dnsrtt_pref_stat_update(stat, 1, 0, 0, 0, 0);
		}
	} else { // UDP queries
	   	// knotd_mod_log(mod, LOG_DEBUG, "(UDP) IP %s, pref %lld, ntcp %lld, lastseen %lld", 
						//addr_str, (long long)bucket->netblk, (long long)bucket->ntcp, (long long)bucket->time);
		// Check number of tcp queries
		// ntcp < rate means we will send back a truncated response of probability of 1/slip percent
		// ntcp >= rate  means we will do nothing
		// ntcp < 0 means something went wrong, report KNOT_ERROR
		if (bucket->ntcp + bucket->tcbit < dnsrtt->rate) {
			// knotd_mod_log(mod, LOG_DEBUG, "Need more TCP queries for pref %lld", (long long)bucket->netblk);
			// knotd_mod_log(mod, LOG_DEBUG, "Slipping a TC bit with the probablity of %.2f percent...", 100.00 * (1.0 / slip));			
			if (dnsrtt_slip_roll(slip)) {	// (1 / slip) percent of unfortunate query
				// knotd_mod_log(mod, LOG_DEBUG, "   !!! Replying a TC bit to pref %lld !!!   ", (long long)bucket->netblk);
				++bucket->tcbit;
				if (bucket->tcbit == 1) {	// first TC bit
					dnsrtt_pref_stat_update(stat, 0, 0, 1, 1, 0);
				} else if (bucket->tcbit == dnsrtt->rate) {
					dnsrtt_pref_stat_update(stat, 0, 0, 1, 0, 1);
				} else {
					dnsrtt_pref_stat_update(stat, 0, 0, 1, 0, 0);
				}
				ret = KNOT_ELIMIT;
			}
		} else if (bucket->ntcp < 0) {
			ret = KNOT_ERROR;
		}
	}

	if (lock > -1) {
		dnsrtt_unlock(dnsrtt, lock);
	}

	// Report and refresh stat
	if (now - start > dnsrtt_INTERVAL) {	// only if stat is older than one interval
		// Lock to report and refresh stat
		pthread_mutex_lock(&stat->ll_str);
		knotd_mod_log(mod, LOG_INFO, "STAT,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld,%lld"
				, (long long)stat->start, (long long)now, (long long)stat->n_query, (long long)stat->n_pref, (long long)stat->n_tcp, 
				(long long)stat->n_pref_valid, (long long)stat->n_tcbit, (long long)stat->n_tcbit_pref, (long long)stat->n_tcbit_pref_valid);
	
		dnsrtt_pref_stat_clear(stat, now);
		pthread_mutex_unlock(&stat->ll_str);

		/*
		pthread_mutex_lock(&dnsrtt->ll);
		FILE *fp;
		fp = fopen("/home/charnset/write_log", "a+");
		fprintf(fp, "ts %lld\n", (long long)now);
		for (int i = 0; i < 16581375; i++) {
			dnsrtt_pref_item_t *bck = &dnsrtt->arr[i];
			if (!bck->netblk) {
				fprintf(fp, "%lld\n", (long long)bck->nquery);
			}
		}
		fclose(fp);
		pthread_mutex_unlock(&dnsrtt->ll);
		*/
	}

	return ret;
}

void dnsrtt_pref_destroy(dnsrtt_pref_table_t *dnsrtt, dnsrtt_pref_stat_t *stat)
{
	if (dnsrtt) {
		if (dnsrtt->lk_count > 0) {
			pthread_mutex_destroy(&dnsrtt->ll);
		}
		for (size_t i = 0; i < dnsrtt->lk_count; ++i) {
			pthread_mutex_destroy(dnsrtt->lk + i);
		}
		free(dnsrtt->lk);
	}

	free(dnsrtt);

	if (stat) {
		pthread_mutex_destroy(&stat->ll_str);
		pthread_mutex_destroy(&stat->ll_nq);
		pthread_mutex_destroy(&stat->ll_nprf);
		pthread_mutex_destroy(&stat->ll_ntcp);
		pthread_mutex_destroy(&stat->ll_nprf_v);
		pthread_mutex_destroy(&stat->ll_ntcbit);
		pthread_mutex_destroy(&stat->ll_ntcbit_prf);
		pthread_mutex_destroy(&stat->ll_ntcbit_pref_v);
	}

	free(stat);
}
