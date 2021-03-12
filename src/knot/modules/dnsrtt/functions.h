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

#pragma once

#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>

#include "libknot/libknot.h"
#include "knot/include/module.h"
#include "contrib/openbsd/siphash.h"

/*!
 * \brief DNSRTT hash bucket.
 */
typedef struct {
	unsigned hop;        // Hop bitmap
	uint64_t netblk;     // Prefix associated
	uint16_t ntcp;       // Number of TCP queries
	uint8_t  cls;        // Bucket class
	uint32_t qname;      // imputed(QNAME) hash
	uint32_t time;       // Timestamp
	uint16_t tcbit;	     // number of received TC bit
} dnsrtt_item_t;

/*!
 * \brief DNSRTT hash bucket table.
 *
 * Table is fixed size, so collisions may occur and are dealt with
 * in a way, that hashbucket rate is reset and enters slow-start for 1 dt.
 * When a bucket is in a slow-start mode, it cannot reset again for the time
 * period.
 *
 * To avoid lock contention, N locks are created and distributed amongst buckets.
 * As of now lock K for bucket N is calculated as K = N % (num_buckets).
 */

typedef struct {
	SIPHASH_KEY key;     // Siphash key
	uint32_t rate;		// Configured number of needed TCP queries per prefix
	pthread_mutex_t ll;	
	pthread_mutex_t *lk;	// Table locks
	unsigned lk_count;	// Table lock count (granularity)
	size_t size;		// Number of buckets
	dnsrtt_item_t arr[];	// Buckets
} dnsrtt_table_t;

/*! \brief DNSRTT request flags. */
typedef enum {
	dnsrtt_REQ_NOFLAG    = 0 << 0, /*!< No flags. */
	dnsrtt_REQ_WILDCARD  = 1 << 1  /*!< Query to wildcard name. */
} dnsrtt_req_flag_t;

/*!
 * \brief DNSRTT request descriptor.
 */
typedef struct {
	const uint8_t *wire;
	uint16_t len;
	dnsrtt_req_flag_t flags;
	knot_pkt_t *query;
	bool tcp;
} dnsrtt_req_t;

/*!
 * \brief Create a DNSRTT table.
 * \param size Fixed hashtable size (reasonable large prime is recommended).
 * \param rate Rate (in pkts/sec).
 * \return created table or NULL.
 */
dnsrtt_table_t *dnsrtt_create(size_t size, uint32_t rate);

/*!
 * \brief Query the DNSRTT table for accept or deny, when the rate limit is reached.
 *
 * \param dnsrtt DNSRTT table.
 * \param slip DNSRTT slip.
 * \param remote Source address.
 * \param req DNSRTT request (containing resp., flags and question).
 • \param zone Zone name related to the response (or NULL).
 * \param mod Query module (needed for logging).
 * \retval KNOT_EOK when did not send back TC bit.
 * \retval KNOT_ELIMIT when sended back TC bit.
 */
int dnsrtt_query(dnsrtt_table_t *dnsrtt, int slip, const struct sockaddr_storage *remote, 
					dnsrtt_req_t *req, const knot_dname_t *zone, knotd_mod_t *mod);

/*!
 * \brief Destroy DNSRTT table.
 */
void dnsrtt_destroy(dnsrtt_table_t *dnsrtt);
