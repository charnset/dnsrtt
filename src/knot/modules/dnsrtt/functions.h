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

typedef struct {
	uint64_t netblk;     // Prefix associated.
	uint16_t ntok;       // Tokens available.
	uint32_t time;       // Timestamp.
} dnsrtt_pref_item_t;

typedef struct {
	uint32_t rate;		// Configured number of needed TCP queries per prefix
	pthread_mutex_t ll;	
	pthread_mutex_t *lk;	// Table locks
	unsigned lk_count;	// Table lock count (granularity)
	size_t size;		// number of buckets
	dnsrtt_pref_item_t arr[];	// buckets array
} dnsrtt_pref_table_t;

/*! \brief DNSRTT request flags. */
typedef enum {
	DNSRTT_REQ_NOFLAG    = 0 << 0, /*!< No flags. */
	DNSRTT_REQ_WILDCARD  = 1 << 1  /*!< Query to wildcard name. */
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
dnsrtt_pref_table_t *dnsrtt_pref_create(size_t size, uint32_t rate);

/*!
 * \brief Query the DNSRTT table for accept or deny, when the rate limit is reached.
 *
 * \param dnsrtt DNSRTT table.
 * \param dnsrtt DNSRTT slip.
 * \param remote Source address.
 * \param req DNSRTT request (containing resp., flags and question).
 * \param mod Query module (needed for logging).
 * \retval KNOT_EOK if passed (limit is reached/enough TCP).
 * \retval KNOT_ELIMIT when needed (need more TCP).
 */
int dnsrtt_pref_query(dnsrtt_pref_table_t *dnsrtt, int slip, const struct sockaddr_storage *remote, dnsrtt_req_t *req, knotd_mod_t *mod);

/*!
 * \brief Roll a dice whether answer slips or not.
 * \param n_slip Number represents every Nth answer that is slipped.
 * \return true or false
 */
// bool dnsrtt_slip_roll(int n_slip);

/*!
 * \brief Destroy DNSRTT table.
 * \param dnsrtt DNSRTT table.
 */
void dnsrtt_pref_destroy(dnsrtt_pref_table_t *dnsrtt);
