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
 * Copyright (c) 2026 Justin Filip and individual contributors
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

#include <jansson.h>

#include "datum_blocktemplates.h"
#include "datum_utils.h"

static void datum_gbt_rules_blake2b_tests(void) {
	json_error_t error;
	json_t *gbt;
	
	gbt = json_loads("{\"rules\":[\"segwit\"]}", 0, &error);
	datum_test(gbt != NULL);
	datum_test(!datum_gbt_rules_want_blake2b(gbt));
	json_decref(gbt);
	
	gbt = json_loads("{\"rules\":[\"segwit\",\"!blake2b\"]}", 0, &error);
	datum_test(gbt != NULL);
	datum_test(datum_gbt_rules_want_blake2b(gbt));
	json_decref(gbt);
	
	gbt = json_loads("{\"rules\":[\"blake2b\",\"segwit\"]}", 0, &error);
	datum_test(gbt != NULL);
	datum_test(datum_gbt_rules_want_blake2b(gbt));
	json_decref(gbt);
	
	gbt = json_loads("{\"rules\":[\"!blake2b-extra\",\"xblake2b\"]}", 0, &error);
	datum_test(gbt != NULL);
	datum_test(!datum_gbt_rules_want_blake2b(gbt));
	json_decref(gbt);
	
	datum_test(!datum_gbt_rules_want_blake2b(NULL));
	gbt = json_object();
	datum_test(gbt != NULL);
	datum_test(!datum_gbt_rules_want_blake2b(gbt));
	json_decref(gbt);
}

static void datum_blocktemplates_abw_mode_tests(void) {
	T_DATUM_TEMPLATE_DATA block_template = {0};
	
	// Local work uses the null XOR key and needs no pool assignment.
	datum_test(datum_blocktemplates_abw_ready(
		&block_template, false, true));
	datum_test(!block_template.abw_enabled);
	datum_test(block_template.abw_assignment_id == 0);
	
	// A pool with ABW disabled also uses the null XOR key.
	datum_test(datum_blocktemplates_abw_ready(
		&block_template, true, false));
	datum_test(!block_template.abw_enabled);
	datum_test(block_template.abw_assignment_id == 0);
	
	// An ABW pool waits for its active assignment.
	datum_test(!datum_blocktemplates_abw_ready(
		&block_template, true, true));
}

// The value a block carrying nothing but its coinbase may pay. Paying under it
// wastes money; paying over it loses the whole block to bad-cb-amount, so every
// case that cannot be derived has to land on the low side.
static void datum_template_subsidy_tests(void) {
	const uint64_t mainnet_subsidy = 312500000ULL;   // block_reward() at height 900000

	// The ordinary case: fees come off coinbasevalue and what is left is subsidy.
	datum_test(datum_template_subsidy_from_fees(
		mainnet_subsidy + 4200000, 4200000, 900000, true) == mainnet_subsidy);

	// A template with no transactions is all subsidy.
	datum_test(datum_template_subsidy_from_fees(
		mainnet_subsidy, 0, 900000, true) == mainnet_subsidy);

	// The regression this exists for. On regtest the halving interval is 150, so at
	// height 235 the subsidy is 25 BTC; block_reward() says 50 because it hardcodes
	// mainnet's 210,000. Deriving it from the template gets it right without the
	// Gateway having to know which chain it is on.
	datum_test(block_reward(235) == 5000000000ULL);
	datum_test(datum_template_subsidy_from_fees(
		2500000000ULL, 0, 235, true) == 2500000000ULL);

	// and with fees on top of that same regtest template.
	datum_test(datum_template_subsidy_from_fees(
		2500000000ULL + 1234, 1234, 235, true) == 2500000000ULL);

	// Fees unknown falls back to the height, which is what this used to do always.
	datum_test(datum_template_subsidy_from_fees(
		mainnet_subsidy + 4200000, 0, 900000, false) == mainnet_subsidy);

	// but the fallback is still capped by the template, so even on a chain whose
	// halving interval it has wrong it cannot ask for more than the block can pay.
	datum_test(datum_template_subsidy_from_fees(
		2500000000ULL, 0, 235, false) == 2500000000ULL);

	// Fees larger than the whole coinbase value are nonsense and must not wrap
	// around into an enormous subsidy.
	datum_test(datum_template_subsidy_from_fees(
		1000, 5000, 900000, true) == 1000);

	// The accessor reads what the parser stored, and tolerates no template.
	{
		T_DATUM_TEMPLATE_DATA tdata = {0};
		tdata.block_subsidy = 1234567;
		datum_test(datum_template_block_subsidy(&tdata) == 1234567);
		datum_test(datum_template_block_subsidy(NULL) == 0);
	}
}

// The same derivation through the real parser, on templates whose transactions
// actually carry fees. The helper tests above check the arithmetic; this checks the
// wiring that feeds it — the per-transaction fee tally and the fees_known flag.
//
// The case that matters for deployment is the mainnet-shaped one. It asserts the
// derived subsidy equals block_reward(), which is what this code used to use
// unconditionally, so a gateway on mainnet builds exactly the coinbase it built
// before. The regtest-shaped cases are where the two deliberately disagree.
static void datum_template_parse_subsidy_tests(void) {
	static const char gbt_fmt[] =
		"{\"rules\":[\"!segwit\",\"!blake2b\"],"
		"\"height\":%u,\"coinbasevalue\":%llu,\"mintime\":1,\"sigoplimit\":80000,"
		"\"curtime\":2000000000,\"sizelimit\":4000000,\"weightlimit\":4000000,"
		"\"version\":536870912,\"bits\":\"1d00ffff\","
		"\"previousblockhash\":\"%064d\",\"target\":\"%064d\","
		"\"default_witness_commitment\":\"6a24aa21a9ed%052d\","
		"\"transactions\":[%s]}";
	// txid and hash must be 64 hex characters; data is the raw transaction
	static const char tx_with_fee[] =
		"{\"txid\":\"%064d\",\"hash\":\"%064d\",\"fee\":%llu,\"sigops\":1,"
		"\"weight\":400,\"data\":\"0100000000\"}";
	static const char tx_no_fee[] =
		"{\"txid\":\"%064d\",\"hash\":\"%064d\",\"sigops\":1,"
		"\"weight\":400,\"data\":\"0100000000\"}";
	char txs[2048], gbt[4096], t1[512], t2[512];
	json_error_t error;
	json_t *j;
	T_DATUM_TEMPLATE_DATA *t;

	datum_test(datum_template_init() > 0);

	// MAINNET SHAPE. Three transactions paying 1000 + 2500 + 7 = 3507 sats of fees on
	// top of the height-900000 subsidy. The derived subsidy must come out exactly at
	// block_reward(900000), because that is what a mainnet gateway used to pay and
	// must keep paying.
	{
		const uint64_t subsidy = block_reward(900000);
		const uint64_t fees = 1000 + 2500 + 7;
		snprintf(t1, sizeof(t1), tx_with_fee, 1, 1, (unsigned long long)1000);
		snprintf(t2, sizeof(t2), tx_with_fee, 2, 2, (unsigned long long)2500);
		char t3[512];
		snprintf(t3, sizeof(t3), tx_with_fee, 3, 3, (unsigned long long)7);
		snprintf(txs, sizeof(txs), "%s,%s,%s", t1, t2, t3);
		snprintf(gbt, sizeof(gbt), gbt_fmt, 900000u,
			(unsigned long long)(subsidy + fees), 0, 0, 0, txs);
		j = json_loads(gbt, 0, &error);
		datum_test(j != NULL);
		t = datum_gbt_parser(j);
		datum_test(t != NULL);
		if (t) {
			datum_test(t->txn_count == 3);
			datum_test(t->txn_total_fee == fees);
			datum_test(t->coinbasevalue == subsidy + fees);
			datum_test(t->block_subsidy == subsidy);
			datum_test(datum_template_block_subsidy(t) == subsidy);
		}
		json_decref(j);
	}

	// REGTEST SHAPE, the regression this fixes. At height 235 the real subsidy is 25
	// BTC; block_reward() says 50 because it assumes mainnet's halving interval.
	// Deriving it from the template gets it right with no idea which chain this is.
	{
		const uint64_t subsidy = 2500000000ULL;
		const uint64_t fees = 1234;
		snprintf(t1, sizeof(t1), tx_with_fee, 1, 1, (unsigned long long)1234);
		snprintf(gbt, sizeof(gbt), gbt_fmt, 235u,
			(unsigned long long)(subsidy + fees), 0, 0, 0, t1);
		j = json_loads(gbt, 0, &error);
		datum_test(j != NULL);
		t = datum_gbt_parser(j);
		datum_test(t != NULL);
		if (t) {
			datum_test(t->txn_total_fee == fees);
			datum_test(t->block_subsidy == subsidy);
			datum_test(block_reward(235) > t->block_subsidy);  // the old value overpaid
		}
		json_decref(j);
	}

	// A transaction whose fee GBT did not report. The tally is then short, so the
	// subtraction would overstate the subsidy and the height-derived value is used
	// instead — clamped to coinbasevalue, so even here it cannot ask for more than
	// the block is able to pay.
	{
		const uint64_t coinbasevalue = 2500001234ULL;
		snprintf(t1, sizeof(t1), tx_with_fee, 1, 1, (unsigned long long)1234);
		snprintf(t2, sizeof(t2), tx_no_fee, 2, 2);
		snprintf(txs, sizeof(txs), "%s,%s", t1, t2);
		snprintf(gbt, sizeof(gbt), gbt_fmt, 235u,
			(unsigned long long)coinbasevalue, 0, 0, 0, txs);
		j = json_loads(gbt, 0, &error);
		datum_test(j != NULL);
		t = datum_gbt_parser(j);
		datum_test(t != NULL);
		if (t) {
			datum_test(t->block_subsidy == coinbasevalue);
			datum_test(t->block_subsidy <= t->coinbasevalue);
		}
		json_decref(j);
	}

	// An empty template is all subsidy, which is the shape the empty-work coinbase is
	// actually built against.
	{
		const uint64_t subsidy = block_reward(900000);
		snprintf(gbt, sizeof(gbt), gbt_fmt, 900000u,
			(unsigned long long)subsidy, 0, 0, 0, "");
		j = json_loads(gbt, 0, &error);
		datum_test(j != NULL);
		t = datum_gbt_parser(j);
		datum_test(t != NULL);
		if (t) {
			datum_test(t->txn_count == 0);
			datum_test(t->txn_total_fee == 0);
			datum_test(t->block_subsidy == subsidy);
		}
		json_decref(j);
	}
}

void datum_blocktemplates_tests(void) {
	datum_gbt_rules_blake2b_tests();
	datum_blocktemplates_abw_mode_tests();
	datum_template_subsidy_tests();
	datum_template_parse_subsidy_tests();
}
