package io.bluewallet.bip324.crypto

import kotlinx.coroutines.runBlocking
import io.bluewallet.bip324.Networks
import io.bluewallet.bip324.bytesToHex
import io.bluewallet.bip324.decodePacket
import io.bluewallet.bip324.deriveKeyMaterial
import io.bluewallet.bip324.deriveSessionKeys
import io.bluewallet.bip324.ellswiftDecode
import io.bluewallet.bip324.ellswiftEcdhXonly
import io.bluewallet.bip324.encodePacket
import io.bluewallet.bip324.helpers.Bip324VectorData
import io.bluewallet.bip324.helpers.FragmentingReader
import io.bluewallet.bip324.helpers.parseCsv
import io.bluewallet.bip324.hexToBytes
import io.bluewallet.bip324.v2Ecdh
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PacketEncodingTest {
    private val magic = Networks.mainnet.magic

    @Test
    fun packetEncodingVectors() {
        runBlocking {
        val rows = parseCsv(Bip324VectorData.packet_encoding_test_vectors)
        for (row in rows) {
            val priv = hexToBytes(row.getValue("in_priv_ours"))
            val ours = hexToBytes(row.getValue("in_ellswift_ours"))
            val theirs = hexToBytes(row.getValue("in_ellswift_theirs"))
            val initiating = row.getValue("in_initiating") == "1"

            assertEquals(row.getValue("mid_x_ours"), bytesToHex(ellswiftDecode(ours)))
            assertEquals(row.getValue("mid_x_theirs"), bytesToHex(ellswiftDecode(theirs)))
            assertEquals(row.getValue("mid_x_shared"), bytesToHex(ellswiftEcdhXonly(theirs, priv)))

            val secret = v2Ecdh(priv, theirs, ours, initiating)
            assertEquals(row.getValue("mid_shared_secret"), bytesToHex(secret))

            val keys = deriveKeyMaterial(secret, magic)
            assertEquals(row.getValue("mid_initiator_l"), bytesToHex(keys.initiatorL))
            assertEquals(row.getValue("mid_initiator_p"), bytesToHex(keys.initiatorP))
            assertEquals(row.getValue("mid_responder_l"), bytesToHex(keys.responderL))
            assertEquals(row.getValue("mid_responder_p"), bytesToHex(keys.responderP))
            assertEquals(row.getValue("out_session_id"), bytesToHex(keys.sessionId))

            val session = deriveSessionKeys(secret, magic, initiating)
            assertEquals(row.getValue("out_session_id"), bytesToHex(session.sessionId))
            assertEquals(row.getValue("mid_send_garbage_terminator"), bytesToHex(session.sendGarbageTerminator))
            assertEquals(row.getValue("mid_recv_garbage_terminator"), bytesToHex(session.recvGarbageTerminator))

            val prior = row.getValue("in_idx").toInt()
            repeat(prior) { encodePacket(session, ByteArray(0)) }

            val unit = hexToBytes(row.getValue("in_contents"))
            val multiply = row.getValue("in_multiply").toInt()
            val contents = ByteArray(unit.size * multiply)
            for (i in 0 until multiply) unit.copyInto(contents, i * unit.size)

            val aad = if (row["in_aad"].orEmpty().isNotEmpty()) hexToBytes(row.getValue("in_aad")) else ByteArray(0)
            val ignore = row.getValue("in_ignore") == "1"
            val ciphertext = encodePacket(session, contents, aad = aad, ignore = ignore)

            val outCiphertext = row["out_ciphertext"].orEmpty()
            if (outCiphertext.isNotEmpty()) {
                assertEquals(outCiphertext, bytesToHex(ciphertext))
            }
            val suffix = row["out_ciphertext_endswith"].orEmpty()
            if (suffix.isNotEmpty()) {
                val suffixBytes = suffix.length / 2
                assertEquals(suffix, bytesToHex(ciphertext.copyOfRange(ciphertext.size - suffixBytes, ciphertext.size)))
            }

            if (outCiphertext.isNotEmpty() && row.getValue("in_ignore") != "1") {
                val sender = deriveSessionKeys(secret, magic, initiating)
                val receiver = deriveSessionKeys(secret, magic, !initiating)
                repeat(prior) {
                    val priorPacket = encodePacket(sender, ByteArray(0))
                    val priorReader = FragmentingReader(priorPacket, 7)
                    decodePacket(receiver, priorReader)
                }
                val packet = hexToBytes(outCiphertext)
                val reader = FragmentingReader(packet, 7)
                val decoded = decodePacket(
                    receiver,
                    reader,
                    io.bluewallet.bip324.DecodePacketOpts(aad = aad),
                )
                assertTrue(decoded.contentEquals(contents))
            }
        }
        }
    }
}
