# bip324

Kotlin Multiplatform **BIP-324** Bitcoin P2P transport + v2 message codec.

This is a port of the TypeScript [`bip324`](https://github.com/Overtorment/bip324) library. The public API matches that package as closely as Kotlin allows: same type names, same functions, same packet and message behaviour, including the official BIP-324 test vectors.

- **Runtime-neutral core** — packet crypto and codecs have no Android/iOS sockets
- **Injected sockets** — implement `ByteDuplex` for OkHttp, Network.framework, Tor, or tests
- **Pure Kotlin crypto** — SHA-256, ChaCha20-Poly1305, ElligatorSwift, and secp256k1 field math
- **Typed payloads** — version, addresses, headers, inventory, transactions, and blocks
- **Official vectors** — every case in `library/src/commonTest/resources/bip324/` runs in the suite

Primary targets are **Android** and **iOS**. JVM and linuxX64 are extra.

## Install

```kotlin
commonMain.dependencies {
    implementation("org.bitcoin.kmp:bip324:0.0.1")
}
```

## Quick usage

```kotlin
import org.bitcoin.bip324.Message
import org.bitcoin.bip324.Networks
import org.bitcoin.bip324.Protocol
import org.bitcoin.bip324.ProtocolOptions
import org.bitcoin.bip324.Role
import org.bitcoin.bip324.pairedByteDuplexes

val (a, b) = pairedByteDuplexes()
val alice = Protocol.connect(a, ProtocolOptions(Role.Initiator, Networks.regtest))
val bob = Protocol.connect(b, ProtocolOptions(Role.Responder, Networks.regtest))

alice.writeMessage(Message.Ping(ByteArray(8)))
val msg = bob.readMessage()
```

Provide your own `ByteDuplex` for real TCP:

```kotlin
interface ByteDuplex {
    // Return 1..n bytes, or an empty array at EOF.
    suspend fun read(n: Int): ByteArray
    suspend fun write(bytes: ByteArray)
    suspend fun close()
}
```

`Protocol.connect` throws `V1DetectedError` without closing the duplex when a
responder detects v1. Lower-level callers can use `performHandshake` to receive
the consumed prefix as a structured `V1HandshakeResult`.

## Layout

```
library/src/commonMain/kotlin/org/bitcoin/bip324/
  crypto/      ElligatorSwift, HKDF, FSChaCha20*
  handshake/   BIP-324 handshake
  packet/      Packet encode/decode
  messages/    Strict framing + typed Bitcoin P2P payload codecs
  session/     Protocol helper
  io/          ByteDuplex + paired in-memory duplexes
```

## Tests

```bash
./gradlew jvmTest
./gradlew linuxX64Test
./gradlew testAndroidHostTest
```

iOS simulator tests require a macOS host: `./gradlew iosSimulatorArm64Test`.
