package org.xmtp.android.library.mesh

import android.content.Context
import android.util.Log
import kotlinx.coroutines.runBlocking
import org.xmtp.android.library.XMTPEnvironment
import uniffi.xmtpv3.carryMeshIdentityLog
import java.io.File

/**
 * Where one inbox's mesh node database lives on this device. `MeshNode::open` binds a node
 * database to one installation for life (the first key package uploaded fixes it), and the
 * libxmtp database `xmtp-MESH-<inboxId>.db3` holds exactly one installation per inbox, so the
 * node is kept per inbox too: files are
 * `xmtp-mesh-node-<inboxId>-<generation>.db3` in [dir], and the inbox's generation is kept in
 * its own pointer file ([pointerName]). A node generation is valid only for the installation
 * that owns that inbox's libxmtp database, so [forClient] moves to a fresh generation whenever
 * that database does not exist yet (a new installation is about to be minted). Other inboxes'
 * nodes are never touched.
 *
 * Not thread-safe on its own: callers must serialize [current], [forClient] and [rotate]
 * against each other and against opening the node (e.g. behind the same lock that serializes
 * client creation and [Mesh.start]/[Mesh.stop]) — a rotate racing a read, or two rotates
 * racing each other, is not guarded here. A rotation deletes the older generations' files; a
 * node that is still open keeps working on its unlinked file until closed, and the next
 * generation is a different path, so the Rust registry (keyed by canonical path) can never hand
 * the stale node to a new installation. Callers must still not rotate an inbox whose node is
 * serving a live client.
 *
 * A rotation that follows the libxmtp database ([forClient], and a host's reset that deletes it)
 * takes an [IdentityLogCarrier]: it copies the inbox's identity log from the retiring generation
 * into the next one before any client opens it, so the new installation publishes
 * `AddAssociation` at the next sequence id instead of a second `CreateInbox` that peers would
 * refuse (DESIGN.md §B10.2, D21). A reset
 * rotates twice (the host's rotate, then [forClient]), and each carries. Recovery rotations
 * ([rotateAll], or [rotate] with no carrier) start empty.
 *
 * [context], when given, is also used to forget the retired generations' BLE short ids
 * ([MeshIdentity], D22) on [rotate], so a rotated-away node's id is never left behind to
 * link it to whatever node replaces it.
 */
class MeshNodeFiles(
    private val dir: File,
    private val inboxId: String,
    // Optional (D22): when given, rotate() also forgets the short id of the generations it
    // retires. Callers that don't have a Context on hand (e.g. plain-JVM tests of file layout
    // alone) still work; they just skip that cleanup.
    private val context: Context? = null,
) {
    init {
        // Letters and digits only: the inbox id is part of file names and of the prefix that
        // selects which files a rotate deletes, so it must never contain '-', '.' or '/'.
        require(INBOX_ID.matches(inboxId)) { "not an inbox id: $inboxId" }
    }

    private val prefix = "$PREFIX$inboxId-"

    /** The node database this inbox's next client should use. */
    fun current(): File = File(dir, "$prefix${generation()}$SUFFIX")

    /**
     * The node for a client about to open [libxmtpDb] (D20): the current generation while
     * that database exists, otherwise a fresh one ([rotate]), because the client is about to
     * mint a new installation that the current node may already refuse ("a mesh node serves
     * exactly one local installation"). With [carrier], the fresh node starts with the inbox's
     * identity log (see the class doc).
     */
    fun forClient(
        libxmtpDb: File,
        carrier: IdentityLogCarrier? = null,
    ): File = if (libxmtpDb.exists()) current() else rotate(carrier)

    /**
     * Moves this inbox to a fresh node database and deletes its older generations with their
     * -wal/-shm files. Call after [Mesh.stop]. A file still open elsewhere keeps working until
     * closed. With [carrier], and when the current generation's file exists, the inbox's identity
     * log is first copied into the next generation. A failed carry is logged and the next
     * generation starts empty (never with a partial log).
     */
    fun rotate(carrier: IdentityLogCarrier? = null): File {
        dir.mkdirs()
        val generation = generation()
        val from = File(dir, "$prefix$generation$SUFFIX")
        val next = File(dir, "$prefix${generation + 1}$SUFFIX")
        if (carrier != null && from.exists()) carryInto(carrier, generation, from, next)
        writePointer(generation + 1)
        val keep = next.name
        dir
            .listFiles()
            ?.filter { it.name.startsWith(prefix) && !it.name.startsWith(keep) }
            ?.forEach { stale ->
                if (!stale.delete()) {
                    Log.w(TAG, "could not delete stale mesh node file ${stale.name}")
                }
                // D22: forget the retired generation's short id too (only for the node db
                // file itself, not its -wal/-shm sidecars, which were never keys).
                if (stale.name.endsWith(SUFFIX)) {
                    context?.let { MeshIdentity.forget(it, stale.name) }
                }
            }
        return current()
    }

    private fun carryInto(
        carrier: IdentityLogCarrier,
        generation: Long,
        from: File,
        next: File,
    ) {
        // Pin the current generation first: with no pointer, generation() falls back to the
        // highest file on disk, and a process death mid-carry must never make the partial next
        // file current.
        writePointer(generation)
        deleteNodeFiles(next) // a partial carry left behind by a process death
        try {
            carrier.carry(from, next, inboxId)
        } catch (e: Exception) {
            Log.w(
                TAG,
                "could not carry the identity log of $inboxId into ${next.name}; its next " +
                    "installation starts on an empty node",
                e,
            )
            deleteNodeFiles(next)
        }
    }

    private fun deleteNodeFiles(node: File) {
        listOf("", "-wal", "-shm", "-journal")
            .map { File(node.path + it) }
            .filter { it.exists() && !it.delete() }
            .forEach { Log.w(TAG, "could not delete mesh node file ${it.name}") }
    }

    /**
     * Writes the pointer atomically: the new value goes to a temp file in the same directory
     * first, then that temp file is renamed over the pointer. A plain `File.writeText` on the
     * pointer would truncate it before writing the new value, so a process death mid-write
     * leaves an empty/corrupt pointer; without the [highestExistingGeneration] fallback in
     * [generation], that would be misread as generation 0 and orphan the real node database
     * (DESIGN.md §B10.1).
     */
    private fun writePointer(value: Long) {
        val pointer = File(dir, pointerName(inboxId))
        val tmp = File.createTempFile("${pointer.name}.", ".tmp", dir)
        tmp.writeText(value.toString())
        if (tmp.renameTo(pointer)) return
        // minSdk 23 predates java.nio.file.Files (API 26) and this module has no core library
        // desugaring, so an atomic rename-over-existing is done with File.renameTo, which on a
        // POSIX filesystem is itself a single rename(2) syscall; some filesystems/API levels
        // still refuse to replace an existing target, so delete and retry once before falling
        // back to a logged, non-atomic copy.
        pointer.delete()
        if (tmp.renameTo(pointer)) return
        Log.w(TAG, "could not atomically replace the mesh node generation pointer; falling back to a direct write")
        tmp.copyTo(pointer, overwrite = true)
        tmp.delete()
    }

    /**
     * The current generation, from this inbox's pointer. If the pointer is missing or
     * unparseable, this recovers the highest generation among the inbox's existing node files
     * instead of assuming 0 — a torn pointer write (process death mid-[rotate]) must never
     * revert to a generation that a real node database has already moved past. 0 only when no
     * node file exists either.
     */
    private fun generation(): Long =
        File(dir, pointerName(inboxId))
            .takeIf { it.isFile }
            ?.readText()
            ?.trim()
            ?.toLongOrNull()
            ?.takeIf { it >= 0 }
            ?: highestExistingGeneration()

    private fun highestExistingGeneration(): Long =
        dir
            .listFiles()
            ?.mapNotNull { file ->
                file.name
                    .takeIf { it.startsWith(prefix) && it.endsWith(SUFFIX) }
                    ?.removePrefix(prefix)
                    ?.removeSuffix(SUFFIX)
                    ?.toLongOrNull()
            }?.maxOrNull() ?: 0L

    companion object {
        private const val TAG = "MeshNodeFiles"
        const val PREFIX = "xmtp-mesh-node-"
        const val SUFFIX = ".db3"
        private const val POINTER_SUFFIX = ".generation"
        private val INBOX_ID = Regex("^[0-9A-Za-z]+$")
        private val NODE_FILE = Regex("^${Regex.escape(PREFIX)}([0-9A-Za-z]+)-[0-9]+${Regex.escape(SUFFIX)}$")
        private val POINTER_FILE = Regex("^${Regex.escape(PREFIX)}([0-9A-Za-z]+)${Regex.escape(POINTER_SUFFIX)}$")

        /** The inbox's generation pointer file name, `xmtp-mesh-node-<inboxId>.generation`. */
        fun pointerName(inboxId: String): String = "$PREFIX$inboxId$POINTER_SUFFIX"

        /** Node files for [inboxId] in the app's default database directory. */
        fun forInbox(
            context: Context,
            inboxId: String,
        ): MeshNodeFiles = MeshNodeFiles(defaultDbDirectory(context), inboxId, context)

        /** `filesDir/xmtp_db`: where [org.xmtp.android.library.Client] keeps its DB without a `dbDirectory`. */
        fun defaultDbDirectory(context: Context): File = File(context.filesDir, "xmtp_db")

        /**
         * The production [IdentityLogCarrier]: the Rust `carry_mesh_identity_log`, opening both
         * node databases with [encryptionKey] (the client's database key). Blocks the calling
         * thread; call it off the main thread, as every rotation already is.
         */
        fun identityLogCarrier(encryptionKey: ByteArray): IdentityLogCarrier =
            IdentityLogCarrier { from, to, inboxId ->
                val held =
                    runBlocking {
                        carryMeshIdentityLog(from.absolutePath, to.absolutePath, encryptionKey, inboxId)
                    }
                Log.i(TAG, "carried $held identity updates of inbox $inboxId into ${to.name}")
            }

        /**
         * The libxmtp database a mesh client for [inboxId] opens in [dbDirectory]; the same name
         * `Client.createFfiClient` builds (`xmtp-${options.api.env}-$inboxId.db3`).
         */
        fun libxmtpDbFile(
            dbDirectory: File,
            inboxId: String,
        ): File = File(dbDirectory, "xmtp-${XMTPEnvironment.MESH}-$inboxId.db3")

        /**
         * Rotates every inbox that has node files or a pointer in [dir]. Recovery only: an inbox
         * whose libxmtp database is kept then reopens on an empty node that does not know its
         * installation. Hosts never need this for correctness, since [forClient] follows the
         * libxmtp database.
         */
        fun rotateAll(
            dir: File,
            context: Context? = null,
        ) {
            val inboxIds =
                dir
                    .listFiles()
                    ?.mapNotNull { file ->
                        (NODE_FILE.matchEntire(file.name) ?: POINTER_FILE.matchEntire(file.name))?.groupValues?.get(1)
                    }?.toSet() ?: emptySet()
            inboxIds.forEach { MeshNodeFiles(dir, it, context).rotate() }
        }
    }
}
