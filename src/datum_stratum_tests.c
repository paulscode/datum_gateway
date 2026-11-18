/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of CONVOY's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://convoy.xyz
 *
 * ---
 *
 * Copyright (c) 2025-2026 Bitcoin Ocean, LLC, Luke Dashjr, and individual contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "datum_conf.h"
#include "datum_api.h"
#include "datum_jsonrpc.h"
#include "datum_pow.h"
#include "datum_protocol.h"
#include "datum_protocol_internal.h"
#include <jansson.h>
#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_utils.h"

void stratum_calculate_merkle_branches(T_DATUM_STRATUM_JOB *s);
void stratum_update_vardiff(T_DATUM_CLIENT_DATA *c, bool no_quick);
int client_mining_submit(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj);
bool stratum_job_coinbaser_ready(T_DATUM_STRATUM_THREADPOOL_DATA *sdata, T_DATUM_STRATUM_JOB *job);

extern uint64_t stratum_latest_empty_complete_count;
extern bool stratum_latest_empty_ready_for_full;
extern uint64_t stratum_latest_empty_job_index;
extern uint64_t stratum_latest_empty_sent_count;
int client_mining_subscribe(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj);

static void datum_blake2b_refresh_time_offset_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	
	/* A job snapshots whether miners may submit a time offset. */
	memset(&tdata, 0, sizeof(tdata));
	memset(&job, 0, sizeof(job));
	job.block_template = &tdata;
	tdata.curtime = 2000000000;
	job.blake2b_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == 2000000000u);
	datum_test(job.blake2b_flags == DATUM_BLAKE2B_USE_TIME_OFFSET);
	
	/* Without the flag the offset is ignored and curtime goes on the wire as is. */
	tdata.curtime = 2000000000;
	job.blake2b_flags = 0;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == 2000000000u);
	
	/* An unrepresentable base time clears the interpretation flag. */
	tdata.curtime = (uint64_t)UINT32_MAX + 1;
	job.blake2b_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == (uint32_t)tdata.curtime);
	datum_test(job.blake2b_flags == 0);
}

static void datum_blake2b_client_pot_commitment_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	unsigned char c_ff[32], c_pot[32], c_variant[32], c_subsidy[32], c_local[32];
	unsigned char c_from_txn[32];
	unsigned char ff[39], pot[39];
	unsigned char cb_txn[64];
	size_t cb_len;
	
	memset(&tdata, 0, sizeof(tdata));
	memset(&job, 0, sizeof(job));
	tdata.version = 0x20000000;
	tdata.height = 12345;
	tdata.bits_uint = 0x1d00ffff;
	tdata.abw_enabled = true;
	tdata.abw_assignment_id = 1;
	datum_test(datum_blake2b_xor_key_hash(
		tdata.xor_key_hash, (const unsigned char[16]){0}));
	job.block_template = &tdata;
	job.is_datum_job = true;
	job.blake2b_time_on_wire = 1000;
	job.coinbase[0].coinb1_len = 20;
	job.coinbase[0].coinb2_len = 8;
	memset(job.coinbase[0].coinb1_bin, 0x11, 20);
	memset(job.coinbase[0].coinb2_bin, 0x22, 8);
	job.coinbase[0].coinb1_bin[4] = 0xFF;
	job.coinbase[COINBASE_TYPE_YUGE] = job.coinbase[0];
	job.coinbase[COINBASE_TYPE_YUGE].coinb2_bin[0] ^= 0x55;
	job.subsidy_only_coinbase = job.coinbase[0];
	job.subsidy_only_coinbase.coinb2_bin[0] ^= 0xaa;
	job.target_pot_index = 4;
	tdata.txn_count = 1;
	
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 0xFF, c_ff, ff));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 14, c_pot, pot));
	datum_test(memcmp(c_ff, c_pot, 32) != 0);
	datum_test(memcmp(ff, pot, 39) != 0);
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[COINBASE_TYPE_YUGE], false, 14, c_variant, NULL));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.subsidy_only_coinbase, true, 14, c_subsidy, NULL));
	datum_test(memcmp(c_variant, c_pot, 32) != 0);
	datum_test(memcmp(c_subsidy, c_pot, 32) != 0);
	
	cb_len = (size_t)job.coinbase[0].coinb1_len + 12 + (size_t)job.coinbase[0].coinb2_len;
	memcpy(cb_txn, job.coinbase[0].coinb1_bin, job.coinbase[0].coinb1_len);
	memset(cb_txn + job.coinbase[0].coinb1_len, 0, 12);
	memcpy(cb_txn + job.coinbase[0].coinb1_len + 12, job.coinbase[0].coinb2_bin, job.coinbase[0].coinb2_len);
	cb_txn[job.target_pot_index] = 14;
	datum_test(datum_stratum_job_blake2b_commitment_from_txn(
		&job, cb_txn, cb_len, 14, false, c_from_txn));
	datum_test(!memcmp(c_from_txn, c_pot, 32));
	
	cb_len = (size_t)job.subsidy_only_coinbase.coinb1_len + 12 +
		(size_t)job.subsidy_only_coinbase.coinb2_len;
	memcpy(cb_txn, job.subsidy_only_coinbase.coinb1_bin,
		job.subsidy_only_coinbase.coinb1_len);
	memset(cb_txn + job.subsidy_only_coinbase.coinb1_len, 0, 12);
	memcpy(cb_txn + job.subsidy_only_coinbase.coinb1_len + 12,
		job.subsidy_only_coinbase.coinb2_bin,
		job.subsidy_only_coinbase.coinb2_len);
	cb_txn[job.target_pot_index] = 14;
	datum_test(datum_stratum_job_blake2b_commitment_from_txn(
		&job, cb_txn, cb_len, 14, true, c_from_txn));
	datum_test(!memcmp(c_from_txn, c_subsidy, 32));
	
	// Work without an assignment commits to the null XOR key.
	tdata.abw_enabled = false;
	tdata.abw_assignment_id = 0;
	job.is_datum_job = false;
	datum_test(datum_stratum_job_blake2b_commitment(
		&job, &job.coinbase[0], false, 14, c_local, NULL));
	datum_test(memcmp(c_local, c_pot, sizeof(c_local)) != 0);
	
	// Pooled work can also operate without ABW.
	job.is_datum_job = true;
	datum_test(datum_stratum_job_blake2b_commitment(
		&job, &job.coinbase[0], false, 14, c_local, NULL));
}

static void datum_blake2b_unmasked_block_tests(void) {
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA block_template = {0};
	unsigned char hash[32] = {0};
	
	job.block_template = &block_template;
	memset(job.block_target, 0xff, sizeof(job.block_target));
	datum_test(datum_stratum_share_is_unmasked_block(&job, hash));
	job.is_datum_job = true;
	datum_test(datum_stratum_share_is_unmasked_block(&job, hash));
	block_template.abw_enabled = true;
	datum_test(!datum_stratum_share_is_unmasked_block(&job, hash));
}

static void datum_blake2b_h_not_zero_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {
		.subscribed = true,
	};
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB *saved_job = global_cur_stratum_jobs[0];
	char submit[] =
		"{\"id\":7,\"method\":\"mining.submit\",\"params\":["
		"\"miner\",\"0000000000c0de00\",\"0000000000000000\","
		"\"00000000\",\"00000000\"]}";
	static const char expected[] =
		"{\"error\":[23,\"H-not-zero\",null],\"id\":7,\"result\":null}\n";
	
	client.app_client_data = &miner;
	job.block_template = &tdata;
	job.target_pot_index = 0;
	job.coinbase[0].coinb1_len = 2;
	job.coinbase[0].coinb1_bin[0] = job.coinbase[0].coinb1_bin[1] = 0xff;
	tdata.abw_enabled = true;
	tdata.abw_assignment_id = 1;
	datum_test(datum_blake2b_xor_key_hash(tdata.xor_key_hash,
		(const unsigned char[16]){0}));
	strcpy(job.job_id, "0000000000c0de00");
	miner.stratum_job_diffs[0] = 1;
	global_cur_stratum_jobs[0] = &job;
	
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit) == 0);
	datum_test(miner.share_count_rejected == 1);
	datum_test(client.out_buf == (int)strlen(expected));
	datum_test(!memcmp(client.w_buffer, expected, strlen(expected)));
	
	global_cur_stratum_jobs[0] = saved_job;
}

// A share that reaches the H-not-zero gate and passes it stops one check later, at
// time-too-old, because the job below sets mintime above the time on its wire. That is
// far enough to tell "the gateway rebuilt the root the miner hashed" from "it didn't",
// and it keeps the test clear of block submission and of the threadpool state the
// checks after it read.
static const char datum_blake2b_share_passed_gate[] =
	"{\"error\":[21,\"time-too-old\",null],\"id\":7,\"result\":null}\n";
static const char datum_blake2b_share_h_not_zero[] =
	"{\"error\":[23,\"H-not-zero\",null],\"id\":7,\"result\":null}\n";

static void datum_blake2b_extranonce2_job(T_DATUM_STRATUM_JOB *job, T_DATUM_TEMPLATE_DATA *tdata) {
	memset(job, 0, sizeof(*job));
	memset(tdata, 0, sizeof(*tdata));
	job->block_template = tdata;
	job->target_pot_index = 0;
	// Two bytes: submit refuses a coinbase slot with coinb1_len < 2 as never generated.
	job->coinbase[0].coinb1_len = 2;
	job->coinbase[0].coinb1_bin[0] = job->coinbase[0].coinb1_bin[1] = 0xff;
	tdata->abw_enabled = true;
	tdata->abw_assignment_id = 1;
	tdata->mintime = 1;
	datum_test(datum_blake2b_xor_key_hash(tdata->xor_key_hash,
		(const unsigned char[16]){0}));
	strcpy(job->job_id, "0000000000c0de00");
}

static void datum_blake2b_extranonce2_submit(T_DATUM_CLIENT_DATA *client,
	const char *extranonce2, const char *nonce, const char *expected) {
	char submit[256];
	snprintf(submit, sizeof(submit),
		"{\"id\":7,\"method\":\"mining.submit\",\"params\":["
		"\"miner\",\"0000000000c0de00\",\"%s\",\"0000000000000000\",\"%s\"]}",
		extranonce2, nonce);
	client->out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(client, submit) == 0);
	datum_test(client->out_buf == (int)strlen(expected));
	datum_test(!memcmp(client->w_buffer, expected, strlen(expected)));
}

// Firmware like the Obelisk SC1 Gen 2 runs a 32-bit nonce2 inside the 8-byte
// extranonce2 this dialect negotiates. It hashes its work root over the value
// zero-padded to 8 bytes, but hex-encodes 8 bytes out of a 4-byte variable, so the high
// 4 bytes on the wire are stack garbage. Read literally they rebuild a different root
// and every share comes back H-not-zero.
//
// Every share here submits the same extranonce2, "deadbeefcafef00d". They differ only
// in which reading of it their nonce was mined against, which is what makes them able
// to tell the two readings apart. Each nonce was found by searching for a BLAKE2b work
// hash with four leading zero bytes against this exact job - roughly 2^32 hashes. To
// regenerate one: build the work root with datum_blake2b_work_root() over the reading
// you want, then search nonce8 through datum_blake2b_build_work_header() and
// datum_blake2b_pow_hash_le() until upk_u32le(share_hash, 28) is zero. The job's
// commitment is b22b63cee7e3bfea12fc2b846246a971406b3a2d7c4b747bb6a9b1683e1ff891.
static void datum_blake2b_extranonce2_zero_extend_tests(void) {
	// mined against extranonce 00000000 deadbeef 00000000 - the zero-extended reading
	static const char nonce_32bit[] = "abbcc51400000007";
	// mined against extranonce 00000000 deadbeef cafef00d - all 8 bytes meant
	static const char nonce_64bit[] = "ebf7861400000009";
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	T_DATUM_STRATUM_JOB job;
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB * const saved_job = global_cur_stratum_jobs[0];

	datum_blake2b_extranonce2_job(&job, &tdata);
	client.app_client_data = &miner;
	miner.subscribed = true;
	miner.stratum_job_diffs[0] = 1;
	global_cur_stratum_jobs[0] = &job;

	// The SC1 case: the share only reconstructs once the high 4 bytes are zeroed.
	// Before the fallback existed this was the H-not-zero frame.
	datum_blake2b_extranonce2_submit(&client, "deadbeefcafef00d", nonce_32bit,
		datum_blake2b_share_passed_gate);
	datum_test(miner.extranonce2_zero_extended_shares == 1);
	datum_test(!miner.extranonce2_64bit);

	// and it keeps working, rather than being a one-off rescue.
	datum_blake2b_extranonce2_submit(&client, "deadbeefcafef00d", nonce_32bit,
		datum_blake2b_share_passed_gate);
	datum_test(miner.extranonce2_zero_extended_shares == 2);

	// A miner that sends the same value with the high bytes already zero is the same
	// share, so it passes as submitted and costs no second hash. It is also no evidence
	// either way about how wide its nonce2 is, so nothing is latched.
	datum_blake2b_extranonce2_submit(&client, "deadbeef00000000", nonce_32bit,
		datum_blake2b_share_passed_gate);
	datum_test(miner.extranonce2_zero_extended_shares == 2);
	datum_test(!miner.extranonce2_64bit);
	
	// A quickdiff (Q) share for a job other than its quickdiff notify's is hashed first, so a
	// block in it would still be submitted, and only then refused as unknown work. The same
	// share for the bound job passes the gate as usual.
	{
		static const char unknown_work[] =
			"{\"error\":[20,\"unknown-work\",null],\"id\":7,\"result\":null}\n";
		char submit[256];
		snprintf(submit, sizeof(submit),
			"{\"id\":7,\"method\":\"mining.submit\",\"params\":["
			"\"miner\",\"Q0000000000c0de00\",\"%s\",\"0000000000000000\",\"%s\"]}",
			"deadbeef00000000", nonce_32bit);
		miner.quickdiff_value = 1;
		miner.quickdiff_commit_value = 0;
		miner.quickdiff_job_index = 5;
		client.out_buf = 0;
		datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit) == 0);
		datum_test(client.out_buf == (int)strlen(unknown_work));
		datum_test(!memcmp(client.w_buffer, unknown_work, strlen(unknown_work)));
		datum_test(miner.last_reject_reason == DATUM_SHARE_REJECT_UNKNOWN_JOB);
		miner.quickdiff_job_index = 0;
		client.out_buf = 0;
		datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit) == 0);
		datum_test(client.out_buf == (int)strlen(datum_blake2b_share_passed_gate));
		datum_test(!memcmp(client.w_buffer, datum_blake2b_share_passed_gate, strlen(datum_blake2b_share_passed_gate)));
		
		// An unbound Q share is rebuilt with the latest quickdiff commitment, which need not
		// be the one the miner hashed. When it does not rebuild, it is still unknown work,
		// not H-not-zero, and the zero-extended retry is neither tried nor counted.
		snprintf(submit, sizeof(submit),
			"{\"id\":7,\"method\":\"mining.submit\",\"params\":["
			"\"miner\",\"Q0000000000c0de00\",\"%s\",\"0000000000000000\",\"%s\"]}",
			"deadbeefcafef00d", nonce_32bit);
		miner.quickdiff_job_index = 5;
		miner.quickdiff_commit_value = 16;
		client.out_buf = 0;
		datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit) == 0);
		datum_test(client.out_buf == (int)strlen(unknown_work));
		datum_test(!memcmp(client.w_buffer, unknown_work, strlen(unknown_work)));
		datum_test(miner.last_reject_reason == DATUM_SHARE_REJECT_UNKNOWN_JOB);
		datum_test(miner.extranonce2_zero_extended_shares == 2);
		datum_test(!miner.extranonce2_64bit);
		
		// A Q share with no quickdiff sent at all, refused by an early check (here a short
		// extranonce2), keeps its answer but is recorded with the unknown-job reason at the
		// difficulty now served, not at the 0 of the quickdiff it doesn't belong to.
		miner.quickdiff_value = 0;
		miner.quickdiff_commit_value = 0;
		miner.quickdiff_job_index = 0;
		miner.last_sent_diff = 64;
		{
			const uint64_t rejected_diff = miner.share_diff_rejected;
			const uint64_t rejected = miner.share_count_rejected;
			snprintf(submit, sizeof(submit),
				"{\"id\":7,\"method\":\"mining.submit\",\"params\":["
				"\"miner\",\"Q0000000000c0de00\",\"dead\",\"0000000000000000\",\"%s\"]}",
				nonce_32bit);
			client.out_buf = 0;
			datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit) == 0);
			datum_test(client.out_buf == (int)strlen(unknown_work));
			datum_test(!memcmp(client.w_buffer, unknown_work, strlen(unknown_work)));
			datum_test(miner.share_count_rejected == rejected + 1);
			datum_test(miner.share_diff_rejected == rejected_diff + 64);
			datum_test(miner.last_reject_reason == DATUM_SHARE_REJECT_UNKNOWN_JOB);
		}
		miner.last_sent_diff = 0;
	}

	// A miner that means all 8 bytes passes on the first reading, so the fallback never
	// runs for it. This is the case that must not regress: it is every device already
	// mining against this gateway.
	{
		T_DATUM_CLIENT_DATA client64 = {0};
		T_DATUM_MINER_DATA miner64 = {0};
		client64.app_client_data = &miner64;
		miner64.subscribed = true;
		miner64.stratum_job_diffs[0] = 1;

		datum_blake2b_extranonce2_submit(&client64, "deadbeefcafef00d", nonce_64bit,
			datum_blake2b_share_passed_gate);
		datum_test(miner64.extranonce2_zero_extended_shares == 0);
		datum_test(miner64.extranonce2_64bit);

		// Having proven it means all 8 bytes, it is never second-guessed again: the
		// share that the fallback would have rescued is rejected instead. Without the
		// latch, a 64-bit miner's bad share could be silently reinterpreted as a
		// different, good one.
		datum_blake2b_extranonce2_submit(&client64, "deadbeefcafef00d", nonce_32bit,
			datum_blake2b_share_h_not_zero);
		datum_test(miner64.extranonce2_zero_extended_shares == 0);
	}

	// A share that is wrong under both readings is still rejected.
	datum_blake2b_extranonce2_submit(&client, "deadbeefcafef00d", "0123456789abcdef",
		datum_blake2b_share_h_not_zero);
	datum_test(miner.extranonce2_zero_extended_shares == 2);

	global_cur_stratum_jobs[0] = saved_job;
}

// The decision on its own, away from the hashing: which submissions have a second
// reading worth trying at all.
static void datum_stratum_extranonce2_zero_extend_unit_tests(void) {
	T_DATUM_MINER_DATA m = {0};
	unsigned char en[12];

	// Garbage in the high 4 bytes is the case this exists for.
	memset(en, 0, sizeof(en));
	memcpy(&en[4], "\xde\xad\xbe\xef\xca\xfe\xf0\x0d", 8);
	datum_test(datum_stratum_extranonce2_zero_extend(&m, en));
	datum_test(!upk_u32le(en, 8));
	datum_test(upk_u32le(en, 4) == upk_u32le((const unsigned char *)"\xde\xad\xbe\xef", 0));

	// Already zero: both readings are the same share, so there is no retry to make.
	datum_test(!datum_stratum_extranonce2_zero_extend(&m, en));

	// A client that has proven it means all 8 bytes is never reinterpreted.
	memcpy(&en[4], "\xde\xad\xbe\xef\xca\xfe\xf0\x0d", 8);
	m.extranonce2_64bit = true;
	datum_test(!datum_stratum_extranonce2_zero_extend(&m, en));
	datum_test(upk_u32le(en, 8) != 0);

	// No client at all is the generic reading, used by nothing today but harmless.
	datum_test(datum_stratum_extranonce2_zero_extend(NULL, en));
	datum_test(!upk_u32le(en, 8));
	datum_test(!datum_stratum_extranonce2_zero_extend(&m, NULL));
}

// Firmware with a hardcoded 32-bit nonce2 rejects the 8-byte extranonce2 this dialect
// normally advertises, so stratum.extranonce2_size lets an operator move the split to
// 8/4 instead. The hasher extranonce stays 12 bytes and the leaf stays 52: the session
// id is padded out to 8 rather than the field being shortened, so the miner
// concatenates coinb1, extranonce1 and extranonce2 exactly as before and arrives at the
// same bytes. What changes is only how much of them it gets to vary.
static void datum_stratum_extranonce2_size_tests(void) {
	// mined against extranonce 00000000 00000000 deadbeef - the 8/4 split
	static const char nonce_4byte[] = "d83fc81800000004";
	// the 4/8 split's own vector, from the tests above
	static const char nonce_32bit[] = "abbcc51400000007";
	const int saved_size = datum_config.stratum_v1_extranonce2_size;
	T_DATUM_MINER_DATA * const m = calloc(1, sizeof(T_DATUM_MINER_DATA));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sd = calloc(1, sizeof(T_DATUM_STRATUM_THREADPOOL_DATA));
	T_DATUM_CLIENT_DATA * const c = calloc(1, sizeof(T_DATUM_CLIENT_DATA));
	T_DATUM_THREAD_DATA * const t = calloc(1, sizeof(T_DATUM_THREAD_DATA));
	T_DATUM_STRATUM_JOB * const job = calloc(1, sizeof(T_DATUM_STRATUM_JOB));
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB * const saved_job = global_cur_stratum_jobs[0];
	assert(m && sd && c && t && job);

	m->sdata = sd;
	c->app_client_data = m;
	c->datum_thread = t;
	c->cid = 1;
	t->app_thread_data = sd;

	// The default split is the one every device already mining against this gateway
	// was told, down to the byte.
	datum_config.stratum_v1_extranonce2_size = 8;
	datum_test(client_mining_subscribe(c, 1, NULL) == 0);
	datum_test(m->extranonce2_size == 8);
	datum_test(strstr(c->w_buffer, "\"b10cf00c\",8]}") != NULL);

	// Moving the split pads the session id out to 8 bytes rather than shortening the
	// 12-byte field, which is what keeps the miner's leaf 52 bytes long.
	memset(c->w_buffer, 0, sizeof(c->w_buffer));
	c->out_buf = 0;
	m->subscribed = false;
	datum_config.stratum_v1_extranonce2_size = 4;
	datum_test(client_mining_subscribe(c, 1, NULL) == 0);
	datum_test(m->extranonce2_size == 4);
	datum_test(strstr(c->w_buffer, "\"b10cf00c00000000\",4]}") != NULL);

	// The session id occupies the first 4 bytes of the hasher extranonce, and the
	// vectors below were mined against a zero one. A real subscribe just handed this
	// connection a real session id, so put it back.
	m->sid = 0;
	m->sid_inv = 0;

	// A share under the 8/4 split reconstructs from the low 4 bytes of the field.
	datum_blake2b_extranonce2_job(job, &tdata);
	global_cur_stratum_jobs[0] = job;
	m->stratum_job_diffs[0] = 1;
	datum_blake2b_extranonce2_submit(c, "deadbeef", nonce_4byte,
		datum_blake2b_share_passed_gate);

	// The zero-extension fallback is for the other split only: here the high 4 bytes
	// are the gateway's own padding, and the miner's value sits below them. Nor is a
	// non-zero value in them evidence that this client means all 8, because under this
	// split they are all it was given.
	datum_test(m->extranonce2_zero_extended_shares == 0);
	datum_test(!m->extranonce2_64bit);
	datum_test(!datum_stratum_extranonce2_zero_extend(m,
		(unsigned char[12]){0,0,0,0, 0,0,0,0, 0xde,0xad,0xbe,0xef}));

	// A miner that ignores the advertised size and sends the other width did not hash
	// the leaf this gateway would rebuild, so it is refused rather than guessed at.
	datum_blake2b_extranonce2_submit(c, "deadbeefcafef00d", nonce_32bit,
		"{\"error\":[20,\"unknown-work\",null],\"id\":7,\"result\":null}\n");

	// and the same refusal the other way round, on a connection told 8.
	m->extranonce2_size = 8;
	datum_blake2b_extranonce2_submit(c, "deadbeef", nonce_4byte,
		"{\"error\":[20,\"unknown-work\",null],\"id\":7,\"result\":null}\n");

	// A connection that never subscribed is refused before its extranonce2 is read.
	// One that is marked subscribed without a size ever being set is read as the
	// default split, so the paths that get there do not change meaning.
	{
		T_DATUM_CLIENT_DATA unsubscribed = {0};
		T_DATUM_MINER_DATA never = {0};
		unsubscribed.app_client_data = &never;
		never.stratum_job_diffs[0] = 1;
		datum_test(never.extranonce2_size == 0);
		datum_blake2b_extranonce2_submit(&unsubscribed, "deadbeefcafef00d", nonce_32bit,
			"{\"error\":[25,\"not-subscribed\",null],\"id\":7,\"result\":null}\n");
		never.subscribed = true;
		datum_blake2b_extranonce2_submit(&unsubscribed, "deadbeefcafef00d", nonce_32bit,
			datum_blake2b_share_passed_gate);
	}

	global_cur_stratum_jobs[0] = saved_job;
	datum_config.stratum_v1_extranonce2_size = saved_size;
	free(job);
	free(t);
	free(c);
	free(sd);
	free(m);
}


static void datum_blake2b_coinbase_selection_tests(void) {
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = calloc(1, sizeof(*sdata));
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_MINER_DATA miner = {.coinbase_selection = COINBASE_TYPE_YUGE};
	
	datum_test(sdata != NULL);
	if (!sdata) return;
	datum_test(datum_stratum_coinbase_index(sdata, &miner, true) == DATUM_COINBASE_ID_EMPTY);
	datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == 0);
	sdata->cur_stratum_job = &job;
	sdata->full_coinbase_ready = true;
	datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == 0);
	job.job_state = JOB_STATE_FULL_PRIORITY_WAIT_COINBASER;
	datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == COINBASE_TYPE_YUGE);
	miner.coinbase_selection = MAX_COINBASE_TYPES;
	datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == 0);
	miner.coinbase_selection = COINBASE_TYPE_YUGE;
	sdata->full_coinbase_ready = false;
	datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == 0);
	
	// Pooled, class 0 (a full template whose coinbase pays only the pool) is
	// never served: until the split is in, the answer is the subsidy-only
	// coinbase, which send_mining_notify serves only on a new block's job and
	// otherwise withholds.
	{
		const int saved_active = atomic_load(&datum_protocol_client_active);
		unsigned char notice[36] = {DATUM_ABW_DRAFT_REVISION, DATUM_ABW_ASSIGNMENT_ACTIVE, 0, 0x5a};
		notice[35] = 0xFE;
		datum_protocol_abw_reset();
		datum_test(datum_protocol_abw_assignment_notice(sizeof(notice), notice));
		atomic_store(&datum_protocol_client_active, 3);
		datum_test(datum_protocol_is_active());
		
		datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == DATUM_COINBASE_ID_EMPTY);
		job.job_state = 0;
		sdata->full_coinbase_ready = true;
		datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == DATUM_COINBASE_ID_EMPTY);
		job.job_state = JOB_STATE_FULL_PRIORITY_WAIT_COINBASER;
		datum_test(datum_stratum_coinbase_index(sdata, &miner, false) == COINBASE_TYPE_YUGE);
		datum_test(datum_stratum_coinbase_index(sdata, &miner, true) == DATUM_COINBASE_ID_EMPTY);
		
		// Pooled, a job never gives up waiting for its coinbaser: giving up is
		// what published the pool-only class. 60 s with the coinbaser still
		// outstanding is not ready, and leaves full_coinbase_ready alone.
		job.global_index = 0;
		job.tsms = 1000;
		job.need_coinbaser = true;
		sdata->loop_tsms = 1000 + 60000;
		sdata->full_coinbase_ready = false;
		datum_test(!stratum_job_coinbaser_ready(sdata, &job));
		datum_test(!sdata->full_coinbase_ready);
		// and once it lands, it is ready.
		job.need_coinbaser = false;
		datum_test(stratum_job_coinbaser_ready(sdata, &job));
		datum_test(sdata->full_coinbase_ready);
		
		// Solo still gives up after 5 s, falling back to class 0, which pays
		// the operator's own address.
		atomic_store(&datum_protocol_client_active, 0);
		job.need_coinbaser = true;
		datum_test(stratum_job_coinbaser_ready(sdata, &job));
		datum_test(!sdata->full_coinbase_ready);
		
		atomic_store(&datum_protocol_client_active, saved_active);
		datum_protocol_abw_reset();
	}
	free(sdata);
}

static void datum_stratum_test_coinbaser_locks(void) {
	// Normally set up when the stratum server starts
	if (atomic_load_explicit(&need_coinbaser_rwlocks_init_done, memory_order_acquire)) return;
	for (int i = 0; i < MAX_STRATUM_JOBS; ++i) {
		pthread_rwlock_init(&need_coinbaser_rwlocks[i], NULL);
	}
	atomic_store_explicit(&need_coinbaser_rwlocks_init_done, true, memory_order_release);
}

static void datum_stratum_coinbaser_ready_tests(void) {
	T_DATUM_STRATUM_THREADPOOL_DATA * const sdata = calloc(1, sizeof(*sdata));
	T_DATUM_STRATUM_JOB job = {0};
	
	datum_test(sdata != NULL);
	if (!sdata) return;
	datum_stratum_test_coinbaser_locks();
	job.tsms = 1000000;
	job.need_coinbaser = true;
	
	// Still waiting on the coinbaser
	sdata->loop_tsms = job.tsms + 4000;
	datum_test(!stratum_job_coinbaser_ready(sdata, &job));
	datum_test(!sdata->full_coinbase_ready);
	
	// Gave up waiting after 5 seconds
	sdata->loop_tsms = job.tsms + 5001;
	datum_test(stratum_job_coinbaser_ready(sdata, &job));
	datum_test(!sdata->full_coinbase_ready);
	
	// A coinbaser that is here gets used, even if the job is first looked at after 5 seconds
	job.need_coinbaser = false;
	datum_test(stratum_job_coinbaser_ready(sdata, &job));
	datum_test(sdata->full_coinbase_ready);
	
	sdata->full_coinbase_ready = false;
	sdata->loop_tsms = job.tsms + 1;
	datum_test(stratum_job_coinbaser_ready(sdata, &job));
	datum_test(sdata->full_coinbase_ready);
	
	free(sdata);
}

static void datum_stratum_new_thread_job_tests(void) {
	// T_DATUM_THREAD_DATA holds MAX_CLIENTS_THREAD client buffers (hundreds of MB), but only its own
	// fields and the first client slot are touched here, and calloc'd memory normally gets backed as used
	T_DATUM_THREAD_DATA * const thread = calloc(1, sizeof(*thread));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sdata = calloc(1, sizeof(*sdata));
	T_DATUM_SOCKET_APP app = {0};
	T_DATUM_MINER_DATA miner;
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB job = {0};
	const global_config_t saved_config = datum_config;
	const int saved_latest_index = global_latest_stratum_job_index;
	T_DATUM_STRATUM_JOB * const saved_job = global_cur_stratum_jobs[0];
	char subscribe[] = "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}";
	
	datum_test(thread != NULL);
	datum_test(sdata != NULL);
	if (!(thread && sdata)) {
		free(thread);
		free(sdata);
		return;
	}
	datum_stratum_test_coinbaser_locks();
	datum_config.stratum_v1_vardiff_min = 1024;
	datum_config.stratum_v1_max_clients_per_thread = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_share_stale_seconds = 60;
	datum_config.bitcoind_work_update_seconds = 40;
	
	// The current job already has its coinbaser, and is older than the 5 second fallback
	tdata.version = 0x20000000;
	tdata.height = 12345;
	tdata.bits_uint = 0x1d00ffff;
	job.block_template = &tdata;
	job.job_state = JOB_STATE_FULL_NORMAL_WAIT_COINBASER;
	job.tsms = current_time_millis() - 10000;
	strcpy(job.job_id, "0000000000c0de");
	job.target_pot_index = 4;
	for (int i = 0; i < MAX_COINBASE_TYPES; ++i) {
		job.coinbase[i].coinb1_len = 20;
		job.coinbase[i].coinb2_len = 8;
		memset(job.coinbase[i].coinb1_bin, 0x11 + i, 20);
		memset(job.coinbase[i].coinb2_bin, 0x22, 8);
	}
	global_cur_stratum_jobs[0] = &job;
	global_latest_stratum_job_index = 0;
	
	// A new stratum thread starts, and loops once before its first client subscribes
	app.max_threads = 1;
	app.max_clients_thread = 1;
	thread->app = &app;
	thread->app_thread_data = sdata;
	datum_stratum_v1_socket_thread_init(thread);
	datum_stratum_v1_socket_thread_loop(thread);
	datum_test(sdata->cur_stratum_job == &job);
	datum_test(sdata->full_coinbase_ready);
	
	T_DATUM_CLIENT_DATA * const client = &thread->client_data[0];
	client->datum_thread = thread;
	client->app_client_data = &miner;
	datum_stratum_v1_socket_thread_client_new(client);
	datum_test(datum_stratum_v1_socket_thread_client_cmd(client, subscribe) == 0);
	client->w_buffer[client->out_buf] = 0;
	
	// Its first job must use the full coinbase (COINBASE_TYPE_YUGE), not the pool-only one (class 0)
	_Static_assert(COINBASE_TYPE_YUGE == 1, "the expected job id below encodes the class");
	const char * const notify = strstr(client->w_buffer, "\"mining.notify\"");
	datum_test(notify && strstr(notify, "[\"0000000000c0de01\","));
	
	T_DATUM_STRATUM_DUPES * const dupes = sdata->dupes;
	if (dupes) free(dupes->ptr);
	free(dupes);
	global_cur_stratum_jobs[0] = saved_job;
	global_latest_stratum_job_index = saved_latest_index;
	datum_config = saved_config;
	free(sdata);
	free(thread);
}

static void datum_stratum_new_thread_empty_work_tests(void) {
	T_DATUM_THREAD_DATA * const thread = calloc(1, sizeof(*thread));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sdata = calloc(1, sizeof(*sdata));
	T_DATUM_SOCKET_APP app = {0};
	T_DATUM_STRATUM_JOB job = {0};
	const global_config_t saved_config = datum_config;
	const int saved_latest_index = global_latest_stratum_job_index;
	T_DATUM_STRATUM_JOB * const saved_job = global_cur_stratum_jobs[0];
	const uint64_t saved_complete_count = stratum_latest_empty_complete_count;
	const bool saved_ready_for_full = stratum_latest_empty_ready_for_full;
	const uint64_t saved_empty_job_index = stratum_latest_empty_job_index;
	const uint64_t saved_sent_count = stratum_latest_empty_sent_count;
	
	datum_test(thread != NULL);
	datum_test(sdata != NULL);
	if (!(thread && sdata)) {
		free(thread);
		free(sdata);
		return;
	}
	datum_config.stratum_v1_max_clients_per_thread = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_share_stale_seconds = 60;
	
	// Empty work for a new block is going out, as set up by update_stratum_job
	job.job_state = JOB_STATE_EMPTY_PLUS;
	global_cur_stratum_jobs[0] = &job;
	global_latest_stratum_job_index = 0;
	stratum_latest_empty_job_index = 0;
	stratum_latest_empty_ready_for_full = false;
	stratum_latest_empty_complete_count = 0;
	stratum_latest_empty_sent_count = 0;
	
	// A thread started now counts towards the threads that have to send it, so it must send
	// it too, or the full work for the block waits for the template thread's timeout
	app.max_threads = 1;
	app.max_clients_thread = 1;
	thread->app = &app;
	thread->app_thread_data = sdata;
	datum_stratum_v1_socket_thread_init(thread);
	datum_stratum_v1_socket_thread_loop(thread);
	datum_test(stratum_latest_empty_complete_count == 1);
	
	T_DATUM_STRATUM_DUPES * const dupes = sdata->dupes;
	if (dupes) free(dupes->ptr);
	free(dupes);
	stratum_latest_empty_job_index = saved_empty_job_index;
	stratum_latest_empty_ready_for_full = saved_ready_for_full;
	stratum_latest_empty_complete_count = saved_complete_count;
	stratum_latest_empty_sent_count = saved_sent_count;
	global_cur_stratum_jobs[0] = saved_job;
	global_latest_stratum_job_index = saved_latest_index;
	datum_config = saved_config;
	free(sdata);
	free(thread);
}

static void datum_stratum_abw_block_request_tests(void) {
	unsigned char xor_key[16];
	unsigned char raw_hash[32], masked_hash[32];
	for (size_t i = 0; i < sizeof(xor_key); ++i) {
		xor_key[i] = (unsigned char)(i + 1);
	}
	for (size_t i = 0; i < sizeof(raw_hash); ++i) {
		raw_hash[i] = (unsigned char)(0x80 + i);
	}
	datum_test(datum_blake2b_apply_xor_mask_le(
		masked_hash, raw_hash, xor_key, 42));
	
	unsigned char header[DATUM_BLAKE2B_BLOCK_HEADER_SIZE] = {0};
	const unsigned char coinbase[] = {1, 0, 0, 0, 0, 0, 0, 0};
	const char transactions_hex[] = "0102";
	char request[2048], original[2048], block_hash[65];
	size_t header_offset = 0;
	header[DATUM_BLAKE2B_HEADER_XOR_CLEAR_BITS_OFFSET] = 42;
	const size_t request_size = datum_stratum_build_block_request_parts(
		request, sizeof(request), header, coinbase, sizeof(coinbase), false,
		1, transactions_hex, sizeof(transactions_hex) - 1, false,
		&header_offset);
	datum_test(request_size > 0);
	datum_test(strstr(request, "0102\"]}") != NULL);
	memcpy(original, request, request_size + 1);
	unsigned char wrong_hash[32];
	memcpy(wrong_hash, masked_hash, sizeof(wrong_hash));
	wrong_hash[0] ^= 1;
	datum_test(!datum_stratum_abw_finalize_block_request(request,
		request_size, header_offset, raw_hash, 42, xor_key,
		wrong_hash, block_hash));
	datum_test(!memcmp(request, original, request_size + 1));
	datum_test(datum_stratum_abw_finalize_block_request(request,
		request_size, header_offset, raw_hash, 42, xor_key,
		masked_hash, block_hash));
	datum_test(!memcmp(request + header_offset +
		DATUM_BLAKE2B_HEADER_XOR_KEY_OFFSET * 2, "01020304", 8));
	for (size_t i = 0; i < sizeof(masked_hash); ++i) {
		datum_test(hex2bin_uchar(block_hash + i * 2) == masked_hash[31 - i]);
	}
}

static void datum_block_coinbase_witness_tests(void) {
	static const unsigned char stripped[] = {
		0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
	};
	static const unsigned char witnessed[] = {
		0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
	};
	static const char zero_witness[] =
		"01200000000000000000000000000000000000000000000000000000000000000000";
	char output[256] = {0};
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB job = {.block_template = &tdata};
	size_t size;
	
	datum_test(!datum_stratum_block_needs_witness(&job, false));
	tdata.default_witness_commitment[0] = '1';
	datum_test(datum_stratum_block_needs_witness(&job, false));
	datum_test(!datum_stratum_block_needs_witness(&job, true));
	datum_test(!datum_stratum_block_needs_witness(NULL, false));
	
	size = datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), stripped, sizeof(stripped), true);
	output[size] = 0;
	datum_test(size == (sizeof(stripped) + 36) * 2);
	datum_test(!strncmp(output, "0100000000010102", 16));
	datum_test(!strncmp(output + 16, zero_witness, sizeof(zero_witness) - 1));
	datum_test(!strcmp(output + 16 + sizeof(zero_witness) - 1, "00000000"));
	
	memset(output, 0, sizeof(output));
	size = datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), witnessed, sizeof(witnessed), true);
	datum_test(size == sizeof(witnessed) * 2);
	datum_test(!strncmp(output, "010000000001010200000000", size));
	
	memset(output, 0, sizeof(output));
	size = datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), stripped, sizeof(stripped), false);
	datum_test(size == sizeof(stripped) * 2);
	datum_test(!strncmp(output, "01000000010200000000", size));
	datum_test(!datum_stratum_coinbase_for_block_hex(
		output, (sizeof(stripped) + 36) * 2 - 1, stripped, sizeof(stripped), true));
	datum_test(!datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), stripped, 7, true));
}

static void datum_stratum_string_request_id_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	char authorize[] =
		"{\"id\":\"authorize-17\",\"method\":\"mining.authorize\","
		"\"params\":[\"hardware.worker\",\"password\"]}";
	char authorize_numeric[] =
		"{\"id\":18,\"method\":\"mining.authorize\","
		"\"params\":[\"hardware.worker\",\"password\"]}";
	char unknown[] =
		"{\"id\":\"unknown-19\",\"method\":\"mining.unknown\",\"params\":[]}";
	char oversized[512];
	
	client.app_client_data = &miner;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, authorize) == 0);
	datum_test(miner.authorized);
	datum_test(!strcmp(miner.last_auth_username, "hardware.worker"));
	datum_test(client.out_buf == (int)strlen("{\"error\":null,\"id\":\"authorize-17\",\"result\":true}\n"));
	datum_test(!memcmp(client.w_buffer,
		"{\"error\":null,\"id\":\"authorize-17\",\"result\":true}\n", client.out_buf));
	datum_test(miner.request_id_json[0] == 0);
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, authorize_numeric) == 0);
	datum_test(client.out_buf == (int)strlen("{\"error\":null,\"id\":18,\"result\":true}\n"));
	datum_test(!memcmp(client.w_buffer,
		"{\"error\":null,\"id\":18,\"result\":true}\n", client.out_buf));
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, unknown) == 0);
	datum_test(client.out_buf == (int)strlen(
		"{\"error\":[-3,\"Method not found\",null],\"id\":\"unknown-19\",\"result\":null}\n"));
	datum_test(!memcmp(client.w_buffer,
		"{\"error\":[-3,\"Method not found\",null],\"id\":\"unknown-19\",\"result\":null}\n",
		client.out_buf));
	datum_test(miner.request_id_json[0] == 0);
	snprintf(oversized, sizeof(oversized),
		"{\"id\":\"%0130d\",\"method\":\"mining.authorize\",\"params\":[]}", 0);
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, oversized) == -4);
}

static void datum_stratum_minimum_difficulty_configure_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	char configure[] =
		"{\"id\":20,\"method\":\"mining.configure\","
		"\"params\":[[\"minimum-difficulty\"],{}]}";
	static const char expected[] =
		"{\"error\":null,\"id\":20,\"result\":{\"minimum-difficulty\":false}}\n";
	
	client.app_client_data = &miner;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, configure) == 0);
	datum_test(client.out_buf == (int)strlen(expected));
	datum_test(!memcmp(client.w_buffer, expected, strlen(expected)));
}


void datum_stratum_mod_username_tests() {
	const char * const s_umods = "{\"x\":{\"addrA\": 0.3}, \"abc\":{\"addrB\":0.3,\"addrC\":0.3},\":)\":{\"\":0.5},\"a.c\":{\"addrD\":1.0}}";
	json_error_t err;
	json_t * const j_umods = JSON_LOADS(s_umods, &err);
	assert(j_umods);
	struct datum_username_mod *umods = NULL;
	int ret = datum_config_parse_username_mods(&umods, j_umods, false);
	assert(ret == 1);
	json_decref(j_umods);
	datum_config.stratum_username_mod = umods;
	
	char buf[0x100];
	char * const pool_addr = datum_config.mining_pool_address;
	char *s, *modname;
	const char *res, *a1, *a2;
	
	strcpy(pool_addr, "dummy");
	
	s = "def~G";
	modname = &s[4];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1) == s);
	
	s = "def~x";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 1) == pool_addr);
	
	s = "def~abc";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3);
	if (0 == strcmp(res, "addrB")) {  // jansson doesn't order keys'
		a1 = "addrB";
		a2 = "addrC";
	} else {
		a1 = "addrC";
		a2 = "addrB";
	}
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3);
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3);
	datum_test(0 == strcmp(res, a2));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3);
	datum_test(0 == strcmp(res, a2));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~abc";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~:)";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	memset(buf, 0, 7);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x7fff, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x8000, modname, 2) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 2) == pool_addr);
	
	s = "xyz~a.c";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3);
	datum_test(0 == strcmp(res, "addrD"));
	
	// Intentionally overflow buf with address: we lose the worker name, but get the full address via its umod buffer
	s = "def.ghi~x";
	modname = &s[8];
	memset(buf, 0x0e, 8);
	res = datum_stratum_mod_username(s, buf, 2, 0, modname, 1);
	datum_test(res != buf);
	datum_test(res != pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	res = datum_stratum_mod_username(s, buf, 2, 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, 2, 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0xffff, modname, 1) == pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(buf[6] == 0x0e);
	res = datum_stratum_mod_username(s, buf, 6, 0, modname, 1);
	datum_test(res == buf);
	datum_test(res != pool_addr);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 1) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "addrA."));
	memset(buf, 0x0e, 10);
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 1) == buf);
	datum_test(buf[9] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.g"));
	memset(buf, 0x0e, 11);
	datum_test(datum_stratum_mod_username(s, buf, 9, 0, modname, 1) == buf);
	datum_test(buf[10] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.gh"));
	memset(buf, 0x0e, 12);
	datum_test(datum_stratum_mod_username(s, buf, 10, 0, modname, 1) == buf);
	datum_test(buf[11] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.ghi"));
	s = "def.ghi~:)";
	modname = &s[8];
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0, modname, 2) == buf);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "d"));
	datum_test(datum_stratum_mod_username(s, buf, 6, 0, modname, 2) == buf);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "def.g"));
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 2) == buf);
	datum_test(buf[7] == 0x0e);
	datum_test(0 == strcmp(res, "def.gh"));
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 2) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "def.ghi"));
}

static void datum_stratum_password_opts_tests(void) {
	T_DATUM_MINER_DATA m;
	const int saved_client_min = datum_config.stratum_v1_vardiff_client_min;
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	const bool saved_password_difficulty = datum_config.stratum_v1_password_difficulty;

	datum_config.stratum_v1_vardiff_client_min = 1024;
	datum_config.stratum_v1_vardiff_min = 16384;

	// Off unless the operator turns it on. Before this the password was discarded, and
	// nobody knows what miners already put in it, so a password that happens to read as
	// a request must change nothing on a Gateway that has not opted in.
	datum_config.stratum_v1_password_difficulty = false;
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "d=8192");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	datum_stratum_apply_password_opts(&m, "fd=8192");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	datum_test(m.client_fixed_diff == false);

	datum_config.stratum_v1_password_difficulty = true;

	// The password miners already send. DATUM ignored it before this existed and must
	// keep ignoring it, or every existing miner's difficulty would move on upgrade.
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "x");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	datum_test(m.client_fixed_diff == false);

	// Neither an absent password nor an empty one is a request for anything.
	datum_stratum_apply_password_opts(&m, NULL);
	datum_test(m.client_min_diff == 0);
	datum_stratum_apply_password_opts(&m, "");
	datum_test(m.client_min_diff == 0);

	// d= sets the starting difficulty and the floor. The floor is the point: without
	// it the first downward vardiff step would clamp back to vardiff_min.
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "d=8192");
	datum_test(m.client_min_diff == 8192);
	datum_test(m.current_diff == 8192);
	datum_test(m.client_fixed_diff == false);

	// fd= is the same value, held. stratum_update_vardiff returns early on this flag.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "fd=8192");
	datum_test(m.client_min_diff == 8192);
	datum_test(m.client_fixed_diff == true);

	// vardiff steps by halving and doubling, so a request that is not a power of two
	// rounds down: erring toward more shares rather than fewer.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=5000");
	datum_test(m.client_min_diff == 4096);

	// A rented rig cannot ask for difficulty 1 and bury the gateway in shares.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1");
	datum_test(m.client_min_diff == 1024);

	// But the limit on requests must not be stricter than what the gateway already
	// gives every client unasked. A Gateway serving small BLAKE2b miners runs
	// vardiff_min at 64 so a slow hasher produces shares on connect; refusing to let
	// one ASK for 512 there would deny a request for strictly less load than the
	// default, which is the wrong way round.
	datum_config.stratum_v1_vardiff_min = 64;
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=512");
	datum_test(m.client_min_diff == 512);
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1");
	datum_test(m.client_min_diff == 64);
	datum_config.stratum_v1_vardiff_min = 16384;

	// Rounding happens before the clamp, so a value just above the client floor
	// cannot round down through it.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1500");
	datum_test(m.client_min_diff == 1024);

	// Asking above vardiff_min is allowed too: this is a floor, not just a way down.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1048576");
	datum_test(m.client_min_diff == 1048576);

	// Unparseable values leave the client where it was rather than at some default.
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "d=abc");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	datum_stratum_apply_password_opts(&m, "d=");
	datum_test(m.client_min_diff == 0);
	datum_stratum_apply_password_opts(&m, "d=0");
	datum_test(m.client_min_diff == 0);

	// Keys this version does not know are skipped rather than aborting the parse, so
	// a newer miner talking to an older gateway still gets the part it understands.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "foo=1,d=8192,bar");
	datum_test(m.client_min_diff == 8192);

	// Both separators, and leading whitespace around a pair.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "u=whatever; d=2048");
	datum_test(m.client_min_diff == 2048);

	// A password longer than the parse buffer must not run off the end of it.
	{
		char big[1024];
		memset(big, 'a', sizeof(big) - 1);
		big[sizeof(big) - 1] = 0;
		memset(&m, 0, sizeof(m));
		datum_stratum_apply_password_opts(&m, big);
		datum_test(m.client_min_diff == 0);
	}

	// An unusable request is ignored rather than clamped to the bound, so the client
	// keeps ordinary vardiff instead of being parked at a difficulty a floor would
	// never let it come back down from.
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "d=35184372088832");   // 2^45
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	// strtoull saturates rather than failing, so a long run of digits arrives as
	// 2^64-1 and must not reach the target maths.
	datum_stratum_apply_password_opts(&m, "d=99999999999999999999999999");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	// and the same for a fixed request
	datum_stratum_apply_password_opts(&m, "fd=35184372088832");
	datum_test(m.client_min_diff == 0);
	datum_test(m.client_fixed_diff == false);
	// The bound does not intrude on anything real. A miner running at an exahash
	// wants roughly 1.4e10 for a share a minute, far below this.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1099511627776");   // 2^40
	datum_test(m.client_min_diff == (1ULL << 40));

	// The key has to be exactly "d" or "fd". A password that merely starts with those
	// letters and happens to contain digits must not be read as a difficulty: without
	// the check on the separator, "d12345" parses as a request for 345.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "diff=8192");
	datum_test(m.client_min_diff == 0);
	datum_stratum_apply_password_opts(&m, "d12345");
	datum_test(m.client_min_diff == 0);
	datum_stratum_apply_password_opts(&m, "fd12345");
	datum_test(m.client_min_diff == 0);
	datum_test(m.client_fixed_diff == false);

	datum_config.stratum_v1_vardiff_client_min = saved_client_min;
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
	datum_config.stratum_v1_password_difficulty = saved_password_difficulty;
}

// A client that asked for a low difficulty has to keep it. Parsing the password is
// only half the feature: vardiff clamps every downward step to a floor, so without a
// per-client floor the request is undone on the first adjustment, which is to say it
// would do nothing for exactly the small miners it is meant to serve.
//
// Only the two downward paths are exercised here. They halve and clamp and return
// without touching a job, so they can be driven with a bare client; the upward and
// quickdiff paths send work and would need the whole template machinery.
static void datum_stratum_client_vardiff_floor_tests(void) {
	const int saved_client_min = datum_config.stratum_v1_vardiff_client_min;
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	const int saved_shares_min = datum_config.stratum_v1_vardiff_target_shares_min;

	T_DATUM_MINER_DATA * const m = calloc(1, sizeof(T_DATUM_MINER_DATA));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sd = calloc(1, sizeof(T_DATUM_STRATUM_THREADPOOL_DATA));
	T_DATUM_CLIENT_DATA * const c = calloc(1, sizeof(T_DATUM_CLIENT_DATA));
	assert(m && sd && c);

	datum_config.stratum_v1_vardiff_client_min = 1024;
	datum_config.stratum_v1_vardiff_min = 16384;
	datum_config.stratum_v1_vardiff_target_shares_min = 8;

	m->sdata = sd;
	c->app_client_data = m;

	// Sixty seconds with no shares is the "difficulty is too high" path.
	sd->loop_tsms = 61000;

	// A client that asked for nothing still gets the operator's floor, unchanged.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->current_diff = m->last_sent_diff = 32768;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 16384);

	// and does not fall through it on the next step either.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->current_diff = m->last_sent_diff = 16384;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 16384);

	// A client that asked for 1024 keeps 1024. Before the per-client floor existed
	// this clamped back up to vardiff_min, which is the bug this feature is about.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->client_min_diff = 1024;
	m->current_diff = m->last_sent_diff = 2048;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 1024);

	// and it is a floor, so it stops there rather than halving on forever.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->current_diff = m->last_sent_diff = 1024;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 1024);

	// fd= holds the difficulty exactly, so this path does not run at all.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->client_min_diff = 1024;
	m->client_fixed_diff = true;
	m->current_diff = m->last_sent_diff = 8192;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 8192);
	m->client_fixed_diff = false;

	// The other downward path: shares arriving slower than twice the target interval.
	// Target is 8 shares/minute, so 7500ms each; 40s per share is far slower.
	m->client_min_diff = 1024;
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 1;
	sd->loop_tsms = 40000;
	m->current_diff = m->last_sent_diff = 2048;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 1024);

	free(c);
	free(sd);
	free(m);

	datum_config.stratum_v1_vardiff_client_min = saved_client_min;
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
	datum_config.stratum_v1_vardiff_target_shares_min = saved_shares_min;
}

/*
 * The reject reasons an operator reads, and the breakdown they read them in.
 *
 * Both are only ever seen when something is already wrong, which is exactly when a wrong
 * name or a truncated one sends someone after the wrong fault.
 */
#ifdef ENABLE_API
bool datum_api_var_STRATUM_REJECT_REASONS(struct buf * const buf, const T_DATUM_API_DASH_VARS *vardata);
#endif

static void datum_stratum_reject_reason_tests(void) {
	// Every reason names itself, and no two share a name
	for (unsigned int i = 0; i < DATUM_SHARE_OUTCOME_COUNT; ++i) {
		const char * const name = datum_stratum_share_reject_name(i);
		datum_test(name != NULL && name[0] != '\0');
		datum_test(strcmp(name, "unknown") != 0);
		for (unsigned int j = i + 1; j < DATUM_SHARE_OUTCOME_COUNT; ++j) {
			datum_test(strcmp(name, datum_stratum_share_reject_name(j)) != 0);
		}
	}
	// Out of range says so rather than reading off the end of the table
	datum_test(!strcmp(datum_stratum_share_reject_name(DATUM_SHARE_OUTCOME_COUNT), "unknown"));
	datum_test(!strcmp(datum_stratum_share_reject_name(60000), "unknown"));

#ifdef ENABLE_API
	// The breakdown is rendered by the dashboard, which a build without the API does not have
	uint64_t saved[DATUM_SHARE_OUTCOME_COUNT];
	for (unsigned int i = 0; i < DATUM_SHARE_OUTCOME_COUNT; ++i) {
		saved[i] = stratum_client_reject_reason_count[i];
		stratum_client_reject_reason_count[i] = 0;
	}

	struct buf b = BUF_INIT;

	// Nothing rejected yet, which is what an operator with no problem sees
	datum_test(datum_api_var_STRATUM_REJECT_REASONS(&b, NULL));
	datum_test(buf_nullterminate(&b)); // struct buf tracks a length; terminate to compare
	datum_test(b.s && !strcmp(b.s, "None"));

	// Listed worst first, so the reason to chase is the one read first
	stratum_client_reject_reason_count[DATUM_SHARE_REJECT_STALE_WORK] = 3;
	stratum_client_reject_reason_count[DATUM_SHARE_REJECT_DUPLICATE] = 900;
	stratum_client_reject_reason_count[DATUM_SHARE_REJECT_ABOVE_TARGET] = 40;
	buf_destroy(&b);
	datum_test(datum_api_var_STRATUM_REJECT_REASONS(&b, NULL));
	datum_test(buf_nullterminate(&b)); // struct buf tracks a length; terminate to compare
	datum_test(b.s && !strcmp(b.s, "duplicate 900, high-hash 40, stale-work 3"));

	// A reason that has not happened is not listed at all
	datum_test(b.s && strstr(b.s, "malformed") == NULL);

	// Every reason at once is listed whole, each with its count. The page buffer grows
	// (struct buf), so there is no truncation to guard against any more.
	for (unsigned int i = DATUM_SHARE_ACCEPTED + 1; i < DATUM_SHARE_OUTCOME_COUNT; ++i) {
		stratum_client_reject_reason_count[i] = 18446744073709551615ULL;
	}
	buf_destroy(&b);
	datum_test(datum_api_var_STRATUM_REJECT_REASONS(&b, NULL));
	datum_test(buf_nullterminate(&b)); // struct buf tracks a length; terminate to compare
	for (unsigned int i = DATUM_SHARE_ACCEPTED + 1; i < DATUM_SHARE_OUTCOME_COUNT; ++i) {
		const char * const name = datum_stratum_share_reject_name(i);
		const char * const found = b.s ? strstr(b.s, name) : NULL;
		datum_test(found != NULL);
		if (found) datum_test(found[strlen(name)] == ' ');
	}
	buf_destroy(&b);

	for (unsigned int i = 0; i < DATUM_SHARE_OUTCOME_COUNT; ++i) {
		stratum_client_reject_reason_count[i] = saved[i];
	}
#endif
}

// Nothing makes a miner subscribe before it authorizes, and some send authorize
// first. Subscribe used to reset the difficulty to vardiff_min unconditionally, so a
// password request read at authorize was lost, and fd=N was lost for good, because a
// fixed difficulty is never varied back. Driven through the real subscribe.
static void datum_stratum_password_before_subscribe_tests(void) {
	const int saved_client_min = datum_config.stratum_v1_vardiff_client_min;
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	const bool saved_password_difficulty = datum_config.stratum_v1_password_difficulty;
	const char * const pws[] = {"fd=65536", "d=8192", "x"};
	const uint64_t want[] = {65536, 8192, 16384};

	datum_config.stratum_v1_vardiff_client_min = 1024;
	datum_config.stratum_v1_vardiff_min = 16384;
	datum_config.stratum_v1_password_difficulty = true;

	for (size_t i = 0; i < sizeof(pws) / sizeof(pws[0]); ++i) {
		T_DATUM_MINER_DATA * const m = calloc(1, sizeof(T_DATUM_MINER_DATA));
		T_DATUM_STRATUM_THREADPOOL_DATA * const sd = calloc(1, sizeof(T_DATUM_STRATUM_THREADPOOL_DATA));
		T_DATUM_CLIENT_DATA * const c = calloc(1, sizeof(T_DATUM_CLIENT_DATA));
		T_DATUM_THREAD_DATA * const t = calloc(1, sizeof(T_DATUM_THREAD_DATA));
		assert(m && sd && c && t);
		m->sdata = sd;
		c->app_client_data = m;
		c->datum_thread = t;
		c->cid = 1;
		t->app_thread_data = sd;

		datum_stratum_apply_password_opts(m, pws[i]);
		datum_test(client_mining_subscribe(c, 1, NULL) == 0);
		datum_test(m->current_diff == want[i]);

		free(t);
		free(c);
		free(sd);
		free(m);
	}

	datum_config.stratum_v1_vardiff_client_min = saved_client_min;
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
	datum_config.stratum_v1_password_difficulty = saved_password_difficulty;
}

// A connection to pooled work while the pool minimum (2^20) is far above the local vardiff
// floor (1024). Set up by pool_min_open, inspected by the test, torn down by pool_min_close.
struct pool_min_fixture {
	T_DATUM_THREAD_DATA *thread;
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata;
	T_DATUM_SOCKET_APP app;
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	T_DATUM_MINER_DATA miner;
	T_DATUM_CLIENT_DATA *client;
	global_config_t saved_config;
	int saved_latest_index;
	T_DATUM_STRATUM_JOB *saved_job;
};

// What the miner has been sent since the last call. Valid until the next send, which starts
// the buffer over.
static const char *pool_min_take_output(struct pool_min_fixture *f) {
	f->client->w_buffer[f->client->out_buf] = 0;
	f->client->out_buf = 0;
	return f->client->w_buffer;
}

static bool pool_min_open(struct pool_min_fixture *f, bool below_pool_min) {
	char subscribe[] = "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}";
	memset(f, 0, sizeof(*f));
	f->thread = calloc(1, sizeof(*f->thread));
	f->sdata = calloc(1, sizeof(*f->sdata));
	datum_test(f->thread != NULL);
	datum_test(f->sdata != NULL);
	if (!(f->thread && f->sdata)) {
		free(f->thread);
		free(f->sdata);
		return false;
	}
	f->saved_config = datum_config;
	f->saved_latest_index = global_latest_stratum_job_index;
	f->saved_job = global_cur_stratum_jobs[0];
	datum_stratum_test_coinbaser_locks();
	datum_config.stratum_v1_vardiff_min = 1024;
	datum_config.override_vardiff_min = UINT64_C(1) << 20;
	datum_config.stratum_v1_vardiff_below_pool_min = below_pool_min;
	datum_config.stratum_v1_max_clients_per_thread = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_share_stale_seconds = 60;
	datum_config.bitcoind_work_update_seconds = 40;

	f->tdata.version = 0x20000000;
	f->tdata.height = 12345;
	f->tdata.bits_uint = 0x1d00ffff;
	f->tdata.txn_count = 1;
	f->job.block_template = &f->tdata;
	f->job.is_datum_job = true;
	f->job.job_state = JOB_STATE_FULL_NORMAL_WAIT_COINBASER;
	f->job.tsms = current_time_millis() - 10000;
	strcpy(f->job.job_id, "0000000000c0de");
	f->job.target_pot_index = 4;
	for (int i = 0; i < MAX_COINBASE_TYPES; ++i) {
		f->job.coinbase[i].coinb1_len = 20;
		f->job.coinbase[i].coinb2_len = 8;
		memset(f->job.coinbase[i].coinb1_bin, 0x11 + i, 20);
		memset(f->job.coinbase[i].coinb2_bin, 0x22, 8);
	}
	global_cur_stratum_jobs[0] = &f->job;
	global_latest_stratum_job_index = 0;

	f->app.max_threads = 1;
	f->app.max_clients_thread = 1;
	f->thread->app = &f->app;
	f->thread->app_thread_data = f->sdata;
	datum_stratum_v1_socket_thread_init(f->thread);
	datum_stratum_v1_socket_thread_loop(f->thread);

	f->client = &f->thread->client_data[0];
	f->client->datum_thread = f->thread;
	f->client->app_client_data = &f->miner;
	datum_stratum_v1_socket_thread_client_new(f->client);
	datum_test(datum_stratum_v1_socket_thread_client_cmd(f->client, subscribe) == 0);
	return true;
}

static void pool_min_close(struct pool_min_fixture *f) {
	T_DATUM_STRATUM_DUPES * const dupes = f->sdata->dupes;
	if (dupes) free(dupes->ptr);
	free(dupes);
	global_cur_stratum_jobs[0] = f->saved_job;
	global_latest_stratum_job_index = f->saved_latest_index;
	datum_config = f->saved_config;
	free(f->sdata);
	free(f->thread);
}

// The coinb1 hex a miner must be sent for the fixture's job at this committed pot, using the
// coinbase the gateway selects for this miner.
static void pool_min_coinb1_hex(struct pool_min_fixture *f, unsigned char pot, char *hex) {
	unsigned char commitment[32], coinb1[39];
	hex[0] = 0;
	const unsigned int cbi = datum_stratum_coinbase_index(f->sdata, &f->miner, false);
	if (cbi >= MAX_COINBASE_TYPES) return;
	if (!datum_stratum_job_blake2b_commitment(&f->job, &f->job.coinbase[cbi], false, pot, commitment, coinb1)) return;
	for (size_t i = 0; i < sizeof(coinb1); ++i) uchar_to_hex(&hex[i << 1], coinb1[i]);
	hex[sizeof(coinb1) << 1] = 0;
}

void reset_vardiff_stats(T_DATUM_CLIENT_DATA *c);
bool stratum_get_job(const T_DATUM_MINER_DATA * const m, const json_t * const job_id, T_DATUM_STRATUM_JOB ** const out_job, uint16_t * const out_job_index, bool * const out_quickdiff, bool * const out_empty_work, uint64_t * const out_job_diff, const uint8_t ** const out_job_target, unsigned char * const out_coinbase_index, T_DATUM_SHARE_OUTCOME * const out_reject);
void stratum_update_vardiff(T_DATUM_CLIENT_DATA *c, bool no_quick);

static void datum_stratum_vardiff_below_pool_min_tests(void) {
	static struct pool_min_fixture f;
	char coinb1_hex[128];
	char nbits[16];
	const char *out;

	// Off (the default): the miner is raised to the pool minimum, as before.
	if (pool_min_open(&f, false)) {
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[1048560]") != NULL);
		datum_test(f.miner.stratum_job_diffs[0] == (UINT64_C(1) << 20));
		datum_test(f.miner.stratum_job_commit_diffs[0] == (UINT64_C(1) << 20));
		pool_min_coinb1_hex(&f, floorPoT(UINT64_C(1) << 20), coinb1_hex);
		datum_test(coinb1_hex[0] && strstr(out, coinb1_hex) != NULL);
		pool_min_close(&f);
	}

	// On: the miner is served its own floor, but the work is still committed to the pool minimum.
	if (pool_min_open(&f, true)) {
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[1023.984375]") != NULL);
		datum_test(strstr(out, "1048560") == NULL);
		datum_test(f.miner.stratum_job_diffs[0] == 1024);
		datum_test(f.miner.stratum_job_commit_diffs[0] == (UINT64_C(1) << 20));
		pool_min_coinb1_hex(&f, floorPoT(UINT64_C(1) << 20), coinb1_hex);
		datum_test(coinb1_hex[0] && strstr(out, coinb1_hex) != NULL);
		// The nbits hint describes the target the miner is asked for, not the commitment.
		snprintf(nbits, sizeof(nbits), "\"%8.8x\"", datum_blake2b_share_nbits(floorPoT(1024)));
		datum_test(strstr(out, nbits) != NULL);

		// A quickdiff that only raises the served difficulty (commitment unchanged at the pool
		// minimum) must not resend the identical work: just the new difficulty goes out, and the
		// miner's current job keeps its easier target so shares in flight still validate.
		f.miner.current_diff = 16384;
		datum_test(send_mining_notify(f.client, true, true, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[16383.75]") != NULL);
		datum_test(strstr(out, "mining.notify") == NULL);
		datum_test(f.miner.quickdiff_active);
		datum_test(f.miner.stratum_job_diffs[0] == 1024);

		// The next regular notify carries the new served difficulty, still committed to the minimum.
		datum_test(send_mining_notify(f.client, false, false, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "mining.notify") != NULL);
		datum_test(!f.miner.quickdiff_active);
		datum_test(f.miner.stratum_job_diffs[0] == 16384);
		datum_test(f.miner.stratum_job_commit_diffs[0] == (UINT64_C(1) << 20));

		// A quickdiff that lifts the served difficulty above the pool minimum changes the
		// commitment, so it is new work and is sent as a quickdiff job as usual.
		f.miner.current_diff = UINT64_C(1) << 22;
		datum_test(send_mining_notify(f.client, true, true, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") != NULL);
		datum_test(f.miner.quickdiff_commit_value == (UINT64_C(1) << 22));
		pool_min_coinb1_hex(&f, floorPoT(UINT64_C(1) << 22), coinb1_hex);
		datum_test(coinb1_hex[0] && strstr(out, coinb1_hex) != NULL);
		pool_min_close(&f);
	}

	// A quickdiff while a newer job is still on its way to the miner (paced, or held for the
	// coinbaser) sends only the new difficulty. The newer job then arrives once, as a regular
	// job at that difficulty, and the job the miner holds keeps its target for shares in flight.
	if (pool_min_open(&f, true)) {
		static T_DATUM_STRATUM_JOB newer;
		T_DATUM_STRATUM_JOB * const saved_slot = global_cur_stratum_jobs[1];
		(void)pool_min_take_output(&f);
		newer = f.job;
		newer.global_index = 1;
		global_cur_stratum_jobs[1] = &newer;
		f.sdata->cur_stratum_job = &newer;
		f.miner.current_diff = 16384;
		datum_test(send_mining_notify(f.client, true, true, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[16383.75]") != NULL);
		datum_test(strstr(out, "mining.notify") == NULL);
		datum_test(f.miner.quickdiff_active);
		datum_test(f.miner.last_sent_stratum_job_index == 0);
		datum_test(f.miner.stratum_job_diffs[0] == 1024);
		datum_test(f.miner.stratum_job_diffs[1] == 0);
		datum_test(send_mining_notify(f.client, false, false, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "mining.notify") != NULL);
		datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") == NULL);
		datum_test(!f.miner.quickdiff_active);
		datum_test(f.miner.last_sent_stratum_job_index == 1);
		datum_test(f.miner.stratum_job_diffs[1] == 16384);
		datum_test(f.miner.stratum_job_commit_diffs[1] == (UINT64_C(1) << 20));
		datum_test(f.miner.stratum_job_diffs[0] == 1024);
		global_cur_stratum_jobs[1] = saved_slot;
		pool_min_close(&f);
	}
	
	// The same holds whatever the difficulties: with the setting off, and with it on once the
	// served difficulty is above the pool minimum, a quickdiff copy of a job still pending
	// would be the same work as the regular job the pacing loop sends after it.
	for (int below = 0; below <= 1; ++below) {
		static T_DATUM_STRATUM_JOB newer;
		T_DATUM_STRATUM_JOB * const saved_slot = global_cur_stratum_jobs[1];
		if (!pool_min_open(&f, below)) continue;
		(void)pool_min_take_output(&f);
		const uint64_t held = f.miner.stratum_job_diffs[0];
		newer = f.job;
		newer.global_index = 1;
		global_cur_stratum_jobs[1] = &newer;
		f.sdata->cur_stratum_job = &newer;
		f.miner.current_diff = UINT64_C(1) << 22;
		datum_test(send_mining_notify(f.client, true, true, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "mining.set_difficulty") != NULL);
		datum_test(strstr(out, "mining.notify") == NULL);
		datum_test(f.miner.quickdiff_active);
		datum_test(f.miner.last_sent_stratum_job_index == 0);
		datum_test(f.miner.stratum_job_diffs[0] == held);
		datum_test(send_mining_notify(f.client, false, false, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "mining.notify") != NULL);
		datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") == NULL);
		datum_test(!f.miner.quickdiff_active);
		datum_test(f.miner.last_sent_stratum_job_index == 1);
		datum_test(f.miner.stratum_job_diffs[1] == (UINT64_C(1) << 22));
		datum_test(f.miner.stratum_job_commit_diffs[1] == (UINT64_C(1) << 22));
		global_cur_stratum_jobs[1] = saved_slot;
		pool_min_close(&f);
	}
	
	// Solo work too: a quickdiff for a job still pending sends only the difficulty, and the job
	// arrives once, as a regular job at the new difficulty.
	if (pool_min_open(&f, true)) {
		static T_DATUM_STRATUM_JOB newer;
		T_DATUM_STRATUM_JOB * const saved_slot = global_cur_stratum_jobs[1];
		(void)pool_min_take_output(&f);
		f.job.is_datum_job = false;
		newer = f.job;
		newer.global_index = 1;
		global_cur_stratum_jobs[1] = &newer;
		f.sdata->cur_stratum_job = &newer;
		f.miner.current_diff = 16384;
		datum_test(send_mining_notify(f.client, true, true, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "mining.set_difficulty") != NULL);
		datum_test(strstr(out, "mining.notify") == NULL);
		datum_test(f.miner.quickdiff_active);
		datum_test(send_mining_notify(f.client, false, false, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "mining.notify") != NULL);
		datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") == NULL);
		datum_test(f.miner.last_sent_stratum_job_index == 1);
		datum_test(f.miner.stratum_job_diffs[1] == 16384);
		datum_test(f.miner.stratum_job_commit_diffs[1] == 16384);
		global_cur_stratum_jobs[1] = saved_slot;
		pool_min_close(&f);
	}
	
	// When the pool minimum has changed since the miner's job was sent, the work that would go
	// out now differs from what it holds, so a served-only quickdiff is still a Q job, committed
	// to the new minimum. The entries for the miner's in-flight shares are left alone.
	if (pool_min_open(&f, true)) {
		(void)pool_min_take_output(&f);
		datum_config.override_vardiff_min = UINT64_C(1) << 21;
		f.miner.current_diff = 16384;
		datum_test(send_mining_notify(f.client, true, true, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") != NULL);
		datum_test(f.miner.quickdiff_commit_value == (UINT64_C(1) << 21));
		datum_test(f.miner.quickdiff_value == 16384);
		pool_min_coinb1_hex(&f, floorPoT(UINT64_C(1) << 21), coinb1_hex);
		datum_test(coinb1_hex[0] && strstr(out, coinb1_hex) != NULL);
		datum_test(f.miner.stratum_job_diffs[0] == 1024);
		datum_test(f.miner.stratum_job_commit_diffs[0] == (UINT64_C(1) << 20));
		pool_min_close(&f);
	}
	
	// After a subsidy-only (new block) job, a served-only quickdiff sends new work instead of
	// leaving the miner on the empty version until the next regular notify.
	if (pool_min_open(&f, true)) {
		(void)pool_min_take_output(&f);
		f.job.subsidy_only_coinbase = f.job.coinbase[0];
		f.job.subsidy_only_coinbase.coinb2_bin[0] ^= 0xaa;
		datum_test(send_mining_notify(f.client, true, false, true) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.notify\",\"params\":[\"N") != NULL);
		datum_test(f.miner.last_sent_subsidy_only);
		f.miner.current_diff = 16384;
		datum_test(send_mining_notify(f.client, true, true, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "mining.notify") != NULL);
		datum_test(!f.miner.last_sent_subsidy_only);
		pool_min_close(&f);
	}

	// Between a new block's subsidy-only blast and the full one, a served-only quickdiff would
	// send the same subsidy-only work again, so it sends only the difficulty. Pooled, a job
	// whose coinbaser is not in yet gets the subsidy-only coinbase.
	if (pool_min_open(&f, true)) {
		const int saved_active = atomic_load(&datum_protocol_client_active);
		unsigned char notice[36] = {DATUM_ABW_DRAFT_REVISION, DATUM_ABW_ASSIGNMENT_ACTIVE, 0, 0x5a};
		notice[35] = 0xFE;
		(void)pool_min_take_output(&f);
		datum_protocol_abw_reset();
		datum_test(datum_protocol_abw_assignment_notice(sizeof(notice), notice));
		atomic_store(&datum_protocol_client_active, 3);
		datum_test(datum_protocol_is_active());
		f.job.subsidy_only_coinbase = f.job.coinbase[0];
		f.job.subsidy_only_coinbase.coinb2_bin[0] ^= 0xaa;
		f.job.is_new_block = true;
		f.job.need_coinbaser = true;
		f.job.tsms = f.sdata->loop_tsms;
		f.sdata->full_coinbase_ready = false;
		datum_test(send_mining_notify(f.client, true, false, true) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.notify\",\"params\":[\"N") != NULL);
		datum_test(f.miner.last_sent_subsidy_only);
		datum_test(datum_stratum_coinbase_index(f.sdata, &f.miner, false) == DATUM_COINBASE_ID_EMPTY);
		f.miner.current_diff = 16384;
		datum_test(send_mining_notify(f.client, true, true, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[16383.75]") != NULL);
		datum_test(strstr(out, "mining.notify") == NULL);
		datum_test(f.miner.quickdiff_active);
		atomic_store(&datum_protocol_client_active, saved_active);
		datum_protocol_abw_reset();
		pool_min_close(&f);
	}
	
	// Off: quickdiff behaves exactly as before (the commitment always moves with it).
	if (pool_min_open(&f, false)) {
		(void)pool_min_take_output(&f);
		f.miner.current_diff = UINT64_C(1) << 22;
		datum_test(send_mining_notify(f.client, true, true, false) == 0);
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") != NULL);
		pool_min_close(&f);
	}

	// With password difficulty on, a rig that asks for d=65536 (what Pickhash sends: the rig's
	// optimal minimum on MRR) is served exactly that, while its work stays committed to the
	// pool minimum. With the option off, the pool minimum overrides the request, as before.
	for (int below = 0; below <= 1; ++below) {
		char authorize[160];
		snprintf(authorize, sizeof(authorize), "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"w\",\"d=65536\"]}");
		if (!pool_min_open(&f, below)) continue;
		datum_config.stratum_v1_password_difficulty = true;
		(void)pool_min_take_output(&f);
		datum_test(datum_stratum_v1_socket_thread_client_cmd(f.client, authorize) == 0);
		out = pool_min_take_output(&f);
		if (below) {
			datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[65535]") != NULL);
			datum_test(f.miner.stratum_job_diffs[0] == 65536);
		} else {
			datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[65535]") == NULL);
			datum_test(f.miner.stratum_job_diffs[0] == (UINT64_C(1) << 20));
		}
		datum_test(f.miner.stratum_job_commit_diffs[0] == (UINT64_C(1) << 20));
		pool_min_close(&f);
	}

	// datum.capabilities reports the features this Gateway has, and whether each is on.
	for (int below = 0; below <= 1; ++below) {
		char caps[] = "{\"id\":7,\"method\":\"datum.capabilities\",\"params\":[]}";
		if (!pool_min_open(&f, below)) continue;
		datum_config.stratum_v1_password_difficulty = !below;
		(void)pool_min_take_output(&f);
		datum_test(datum_stratum_v1_socket_thread_client_cmd(f.client, caps) == 0);
		out = pool_min_take_output(&f);
		json_error_t err;
		json_t * const reply = json_loads(out, JSON_DISABLE_EOF_CHECK, &err);
		datum_test(reply != NULL);
		json_t * const result = reply ? json_object_get(reply, "result") : NULL;
		json_t * const feats = result ? json_object_get(result, "features") : NULL;
		datum_test(reply && json_integer_value(json_object_get(reply, "id")) == 7);
		datum_test(feats && json_is_true(json_object_get(feats, "reject_tls_probe")));
		datum_test(feats && json_is_boolean(json_object_get(feats, "vardiff_below_pool_min")) &&
			json_boolean_value(json_object_get(feats, "vardiff_below_pool_min")) == (bool)below);
		datum_test(feats && json_boolean_value(json_object_get(feats, "password_difficulty")) == !below);
		datum_test(result && !strcmp(json_string_value(json_object_get(result, "algo")) ?: "", "blake2b"));
		datum_test(result && json_is_integer(json_object_get(result, "pool_min_diff")));
		json_decref(reply);
		pool_min_close(&f);
	}

	// Vardiff measures the difficulty now served. Seen live: shares from a job at the old,
	// easier difficulty, counted after a step up, made a quickdiff jump 16384 -> 262144.
	if (pool_min_open(&f, true)) {
		T_DATUM_MINER_DATA * const m = &f.miner;
		(void)pool_min_take_output(&f);
		// Sending a new difficulty starts the measurement over.
		m->share_count_since_snap = 250;
		m->share_count_old_diff_since_snap = 3;
		m->current_diff = 16384;
		datum_test(send_mining_set_difficulty(f.client) == 0);
		datum_test(m->share_count_since_snap == 0 && m->share_count_old_diff_since_snap == 0);
		// A share from an older, easier job is accepted but not counted toward the rate.
		datum_stratum_count_vardiff_share(m, 8192);
		datum_test(m->share_count_since_snap == 0 && m->share_count_old_diff_since_snap == 1);
		datum_stratum_count_vardiff_share(m, 16384);
		datum_test(m->share_count_since_snap == 1 && m->share_diff_since_snap == 16384);
		// Nine quick old-job shares cannot trigger a quickdiff.
		reset_vardiff_stats(f.client);
		m->share_snap_tsms = m->sdata->loop_tsms - 2000;
		for (int i = 0; i < 9; ++i) datum_stratum_count_vardiff_share(m, 8192);
		stratum_update_vardiff(f.client, false);
		datum_test(m->current_diff == 16384);
		// Over a minute with only old-job shares is not silence: no step down, but the
		// count is cleared, so it buys one minute at most.
		m->share_snap_tsms = m->sdata->loop_tsms - 70000;
		stratum_update_vardiff(f.client, true);
		datum_test(m->current_diff == 16384);
		datum_test(m->share_count_old_diff_since_snap == 0);
		// A miner that then finds nothing at all is stepped down a minute later, as before
		// (seen in review: a single in-flight old share used to block this indefinitely).
		m->share_snap_tsms = m->sdata->loop_tsms - 70000;
		stratum_update_vardiff(f.client, true);
		datum_test(m->current_diff == 8192);
		m->current_diff = m->last_sent_diff = 16384;
		// A minute of true silence still steps down, as before.
		reset_vardiff_stats(f.client);
		m->share_snap_tsms = m->sdata->loop_tsms - 70000;
		stratum_update_vardiff(f.client, true);
		datum_test(m->current_diff == 8192);
		pool_min_close(&f);
	}

	// Credit: a share is credited at the difficulty now served when it meets it (a miner that
	// applied a new set_difficulty while still on the older job), otherwise at the job's.
	{
		uint8_t t_old[32], t_new[32];
		datum_test(datum_blake2b_share_target(t_old, floorPoT(1024)));
		datum_test(datum_blake2b_share_target(t_new, floorPoT(16384)));
		datum_test(datum_stratum_share_credit_diff(t_new, 1024, 16384) == 16384);
		// Missing the served target: accepted, credited at nothing (unbiased; see the helper).
		datum_test(datum_stratum_share_credit_diff(t_old, 1024, 16384) == 0);
		datum_test(datum_stratum_share_credit_diff(t_new, 16384, 1024) == 16384);
	}

	// A quickdiff (Q) share is only for the job its quickdiff notify was sent for. The job lookup
	// still resolves a Q share for another job, so client_mining_submit can try it as a block
	// before refusing it; datum_stratum_quickdiff_for_job is what refuses it.
	if (pool_min_open(&f, true)) {
		char qid[40];
		T_DATUM_STRATUM_JOB *jout = NULL;
		uint16_t jidx = 0;
		bool q = false, empty = false;
		uint64_t jdiff = 0;
		const uint8_t *jtarget = NULL;
		unsigned char cbi = 0;
		T_DATUM_SHARE_OUTCOME rej;
		snprintf(qid, sizeof(qid), "Q%s%2.2x", f.job.job_id, (unsigned)datum_stratum_coinbase_index(f.sdata, &f.miner, false));
		json_t * const jid = json_string(qid);
		f.miner.quickdiff_value = 4096;
		f.miner.quickdiff_job_index = 7;
		datum_test(stratum_get_job(&f.miner, jid, &jout, &jidx, &q, &empty, &jdiff, &jtarget, &cbi, &rej) && q && jidx == 0);
		datum_test(!datum_stratum_quickdiff_for_job(&f.miner, jidx));
		f.miner.quickdiff_job_index = 0;
		datum_test(stratum_get_job(&f.miner, jid, &jout, &jidx, &q, &empty, &jdiff, &jtarget, &cbi, &rej) && q && jdiff == 4096);
		datum_test(datum_stratum_quickdiff_for_job(&f.miner, jidx));
		f.miner.quickdiff_value = 0;
		datum_test(!datum_stratum_quickdiff_for_job(&f.miner, jidx));
		json_decref(jid);
		pool_min_close(&f);
	}

	// A fixed difficulty (fd=) keeps the pool minimum as its floor even with the option on:
	// with vardiff off, nothing else would stop a fixed low difficulty becoming a flood.
	if (pool_min_open(&f, true)) {
		(void)pool_min_take_output(&f);
		f.miner.client_fixed_diff = true;
		datum_test(send_mining_notify(f.client, false, false, false) == 0);
		datum_test(f.miner.stratum_job_diffs[0] == (UINT64_C(1) << 20));
		pool_min_close(&f);
	}

	// Forwarding: only a share meeting the committed target goes to the pool.
	uint8_t served[32], committed[32];
	datum_test(datum_blake2b_share_target(served, floorPoT(1024)));
	datum_test(datum_blake2b_share_target(committed, floorPoT(UINT64_C(1) << 20)));
	datum_test(datum_stratum_share_forwardable(committed, 1024, UINT64_C(1) << 20));
	datum_test(!datum_stratum_share_forwardable(served, 1024, UINT64_C(1) << 20));
	// With no split (commit == served), every accepted share is forwarded, as before.
	datum_test(datum_stratum_share_forwardable(served, 1024, 1024));
	datum_test(datum_stratum_share_forwardable(served, 1024, 0));
	
	// A kept share the pool would take no share for is answered as a forwarded one would be:
	// stale-work for a disclosed assignment, unknown-work for none. Forwarded and local
	// shares are left to the caller.
	if (pool_min_open(&f, true)) {
		(void)pool_min_take_output(&f);
		datum_test(datum_stratum_refuse_kept_share(f.client, 9, DATUM_SHARE_ROUTE_STALE, 1024));
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"error\":[21,\"stale-work\",null]") != NULL);
		datum_test(f.miner.last_reject_reason == DATUM_SHARE_REJECT_STALE_WORK);
		datum_test(datum_stratum_refuse_kept_share(f.client, 9, DATUM_SHARE_ROUTE_REFUSE, 1024));
		out = pool_min_take_output(&f);
		datum_test(strstr(out, "\"error\":[20,\"unknown-work\",null]") != NULL);
		datum_test(f.miner.last_reject_reason == DATUM_SHARE_REJECT_POOL_SUBMIT);
		datum_test(f.miner.share_count_rejected == 2);
		datum_test(!datum_stratum_refuse_kept_share(f.client, 9, DATUM_SHARE_ROUTE_FORWARD, 1024));
		datum_test(!datum_stratum_refuse_kept_share(f.client, 9, DATUM_SHARE_ROUTE_LOCAL, 1024));
		out = pool_min_take_output(&f);
		datum_test(out[0] == 0);
		datum_test(f.miner.share_count_rejected == 2);
		pool_min_close(&f);
	}
	
	// Routing: a share meeting the commitment is forwarded and one below it is kept local,
	// unless the pool would refuse any share for the job, as under anti-withholding without an
	// assignment. Then it is refused here too, as it would have been when forwarded.
	{
		static T_DATUM_TEMPLATE_DATA rt;
		static T_DATUM_STRATUM_JOB rj;
		memset(&rt, 0, sizeof(rt));
		memset(&rj, 0, sizeof(rj));
		rj.block_template = &rt;
		rj.is_datum_job = true;
		datum_test(datum_stratum_share_route(&rj, committed, 1024, UINT64_C(1) << 20) == DATUM_SHARE_ROUTE_FORWARD);
		datum_test(datum_stratum_share_route(&rj, served, 1024, UINT64_C(1) << 20) == DATUM_SHARE_ROUTE_LOCAL);
		datum_test(datum_stratum_share_route(&rj, served, 1024, 1024) == DATUM_SHARE_ROUTE_FORWARD);
		rt.abw_enabled = true;
		datum_test(datum_stratum_share_route(&rj, served, 1024, UINT64_C(1) << 20) == DATUM_SHARE_ROUTE_REFUSE);
		// A share meeting the commitment, as every block does, is never answered as a kept
		// share, even for a job the pool would take no share for: it goes to
		// datum_protocol_pow_submit, which answers it.
		datum_test(datum_stratum_share_route(&rj, committed, 1024, UINT64_C(1) << 20) == DATUM_SHARE_ROUTE_FORWARD);
		rj.is_datum_job = false;
		datum_test(datum_stratum_share_route(&rj, served, 1024, UINT64_C(1) << 20) == DATUM_SHARE_ROUTE_LOCAL);
	}
}

void datum_stratum_tests(void) {
	datum_stratum_vardiff_below_pool_min_tests();
	datum_stratum_reject_reason_tests();
	datum_stratum_password_opts_tests();
	datum_stratum_password_before_subscribe_tests();
	datum_stratum_client_vardiff_floor_tests();
	datum_stratum_mod_username_tests();
	datum_stratum_minimum_difficulty_configure_tests();
	datum_stratum_string_request_id_tests();
	datum_blake2b_coinbase_selection_tests();
	datum_stratum_coinbaser_ready_tests();
	datum_stratum_new_thread_job_tests();
	datum_stratum_new_thread_empty_work_tests();
	datum_blake2b_h_not_zero_tests();
	datum_stratum_extranonce2_zero_extend_unit_tests();
	datum_blake2b_extranonce2_zero_extend_tests();
	datum_stratum_extranonce2_size_tests();
	datum_blake2b_client_pot_commitment_tests();
	datum_blake2b_unmasked_block_tests();
	datum_stratum_abw_block_request_tests();
	datum_blake2b_refresh_time_offset_tests();
	datum_block_coinbase_witness_tests();
}
