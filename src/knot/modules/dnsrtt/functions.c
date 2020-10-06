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

static int dnsrtt_pref_setlocks(dnsrtt_pref_table_t *pref_tbl, uint32_t granularity)
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

dnsrtt_pref_table_t *dnsrtt_pref_create(size_t size, uint32_t rate)
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

	if (dnsrtt_pref_setlocks(pref_tbl, dnsrtt_LOCK_GRANULARITY) != KNOT_EOK) {
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
	knotd_mod_log(mod, LOG_DEBUG, "pref (in network byteorder, adjust masks) %lld : id %lld", (long long)netblk, (long long)id);

	// Lock for lookup
	// pthread_mutex_lock(&tbl->ll);

	// Assign granular lock and unlock lookup
	// *lock = id % tbl->lk_count;
	// dnsrtt_lock(tbl, *lock);
	// pthread_mutex_unlock(&tbl->ll);

	// Find bucket 
	dnsrtt_pref_item_t *bucket = &tbl->arr[id];

	// Check whether bucket is empty or not
	if (!bucket->netblk && !bucket->ntok && !bucket->time) {
		knotd_mod_log(mod, LOG_DEBUG, "Initiating an empty bucket...");
		bucket->netblk = netblk;
		bucket->ntok = tbl->rate;
		bucket->time = stamp;
	}

	return bucket;
}


int dnsrtt_pref_query(dnsrtt_pref_table_t *dnsrtt, int slip, const struct sockaddr_storage *remote, dnsrtt_req_t *req, knotd_mod_t *mod)
{	
	if (!dnsrtt || !req || !remote) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	// Query detail
	char addr_str[SOCKADDR_STRLEN];
	subnet_tostr(addr_str, sizeof(addr_str), remote);
	if (req->tcp) {	// Skip TCP query
		knotd_mod_log(mod, LOG_DEBUG, "TCP query : IP %s", addr_str);
		return ret;
		
	} else {
		knotd_mod_log(mod, LOG_DEBUG, "UDP query : IP %s", addr_str);
	}
	
	//  Fetch bucket
	int lock = -1;
	uint32_t now = time_now().tv_sec;
	dnsrtt_pref_item_t *bucket = dnsrtt_pref_id(dnsrtt, remote, req, now, &lock, mod);
	
	if (!bucket) {
		return KNOT_ERROR;
	}

	// Visit bucket
	knotd_mod_log(mod, LOG_DEBUG, "Visiting a bucket...");
	knotd_mod_log(mod, LOG_DEBUG, "pref %lld, ntok %lld, lastseen %lld", (long long)bucket->netblk, (long long)bucket->ntok, (long long)bucket->time);
	
	// Check number of tokens
	// ntok > 0 means we will send back a truncated response of probability of 1/slip percent
	// ntok = 0 means we will do nothing, unless lastseen is more than an hour we will do the same as ntok > 0
	// ntok < 0 means something went wrong, report KNOT_ERROR
	if (bucket->ntok > 0) {
		knotd_mod_log(mod, LOG_DEBUG, "Replying back a truncated bit with the probablity of %.2f percent...", 100.00 * (1.0 / slip));
		if (dnsrtt_slip_roll(slip)) {	// (1 / slip) percent of unfortunate query
			--bucket->ntok; // update bucket ntok (decreasing)
			bucket->time = now;	// update lastseen (upcoming TCP)
			ret = KNOT_ELIMIT;
		}
	} else if (bucket->ntok == 0) {
		if (now - bucket->time > 3600) {
			knotd_mod_log(mod, LOG_DEBUG, "Replying back a truncated bit with the probablity of %.2f percent...", 100.00 * (1.0 / slip));
			if (dnsrtt_slip_roll(slip)) {	// (1 / slip) percent of unfortunate query
				bucket->ntok = dnsrtt->rate - 1; // restore and update bucket ntok (decreasing)
				bucket->time = now;	// update lastseen (upcoming TCP)
				ret = KNOT_ELIMIT;
			}
		}
	} else {
		ret = KNOT_ERROR;
	}

	return ret;
}

void dnsrtt_pref_destroy(dnsrtt_pref_table_t *dnsrtt)
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
}
