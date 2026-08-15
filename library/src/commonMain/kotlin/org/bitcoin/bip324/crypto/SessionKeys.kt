package org.bitcoin.bip324

class SessionKeyMaterial(
    val sessionId: ByteArray,
    val initiatorL: ByteArray,
    val initiatorP: ByteArray,
    val responderL: ByteArray,
    val responderP: ByteArray,
    val initiatorGarbageTerminator: ByteArray,
    val responderGarbageTerminator: ByteArray,
)

class CipherSession(
    val sessionId: ByteArray,
    val sendL: FSChaCha20,
    val sendP: FSChaCha20Poly1305,
    val recvL: FSChaCha20,
    val recvP: FSChaCha20Poly1305,
    val sendGarbageTerminator: ByteArray,
    val recvGarbageTerminator: ByteArray,
)

/** Derive BIP-324 transport keys from ECDH secret and network magic. */
fun deriveSessionKeys(
    ecdhSecret: ByteArray,
    networkMagic: ByteArray,
    initiating: Boolean,
): CipherSession {
    val salt = concatBytes(utf8ToBytes("bitcoin_v2_shared_secret"), networkMagic)
    fun expand(info: String, length: Int) = hkdfSha256(ecdhSecret, salt, info, length)

    val initiatorL = expand("initiator_L", 32)
    val initiatorP = expand("initiator_P", 32)
    val responderL = expand("responder_L", 32)
    val responderP = expand("responder_P", 32)
    val garbageTerminators = expand("garbage_terminators", 32)
    val sessionId = expand("session_id", 32)
    val initiatorGarbageTerminator = garbageTerminators.copyOfRange(0, 16)
    val responderGarbageTerminator = garbageTerminators.copyOfRange(16, 32)

    val session = if (initiating) {
        CipherSession(
            sessionId = sessionId,
            sendL = FSChaCha20(initiatorL),
            sendP = FSChaCha20Poly1305(initiatorP),
            recvL = FSChaCha20(responderL),
            recvP = FSChaCha20Poly1305(responderP),
            sendGarbageTerminator = initiatorGarbageTerminator,
            recvGarbageTerminator = responderGarbageTerminator,
        )
    } else {
        CipherSession(
            sessionId = sessionId,
            sendL = FSChaCha20(responderL),
            sendP = FSChaCha20Poly1305(responderP),
            recvL = FSChaCha20(initiatorL),
            recvP = FSChaCha20Poly1305(initiatorP),
            sendGarbageTerminator = responderGarbageTerminator,
            recvGarbageTerminator = initiatorGarbageTerminator,
        )
    }

    initiatorL.fillZero()
    initiatorP.fillZero()
    responderL.fillZero()
    responderP.fillZero()
    garbageTerminators.fillZero()
    return session
}

/** Best-effort erasure of all transport secrets held by a session. */
fun destroySession(session: CipherSession) {
    session.sendL.destroy()
    session.sendP.destroy()
    session.recvL.destroy()
    session.recvP.destroy()
    session.sessionId.fillZero()
    session.sendGarbageTerminator.fillZero()
    session.recvGarbageTerminator.fillZero()
}

/** Expose mid-state key material for vector tests. */
fun deriveKeyMaterial(
    ecdhSecret: ByteArray,
    networkMagic: ByteArray,
): SessionKeyMaterial {
    val salt = concatBytes(utf8ToBytes("bitcoin_v2_shared_secret"), networkMagic)
    fun expand(info: String, length: Int) = hkdfSha256(ecdhSecret, salt, info, length)
    val garbageTerminators = expand("garbage_terminators", 32)
    return SessionKeyMaterial(
        sessionId = expand("session_id", 32),
        initiatorL = expand("initiator_L", 32),
        initiatorP = expand("initiator_P", 32),
        responderL = expand("responder_L", 32),
        responderP = expand("responder_P", 32),
        initiatorGarbageTerminator = garbageTerminators.copyOfRange(0, 16),
        responderGarbageTerminator = garbageTerminators.copyOfRange(16, 32),
    )
}
