package org.bitcoin.bip324

/** BIP-324 short message type IDs (1-byte). 0 means 12-byte ASCII follows. */
val SHORT_MESSAGE_IDS: Map<String, Int> = mapOf(
    "addr" to 1,
    "block" to 2,
    "blocktxn" to 3,
    "cmpctblock" to 4,
    "feefilter" to 5,
    "filteradd" to 6,
    "filterclear" to 7,
    "filterload" to 8,
    "getblocks" to 9,
    "getblocktxn" to 10,
    "getdata" to 11,
    "getheaders" to 12,
    "headers" to 13,
    "inv" to 14,
    "mempool" to 15,
    "merkleblock" to 16,
    "notfound" to 17,
    "ping" to 18,
    "pong" to 19,
    "sendcmpct" to 20,
    "tx" to 21,
    "getcfilters" to 22,
    "cfilter" to 23,
    "getcfheaders" to 24,
    "cfheaders" to 25,
    "getcfcheckpt" to 26,
    "cfcheckpt" to 27,
    "addrv2" to 28,
)

val SHORT_ID_TO_COMMAND: Map<Int, String> =
    SHORT_MESSAGE_IDS.entries.associate { (cmd, id) -> id to cmd }
