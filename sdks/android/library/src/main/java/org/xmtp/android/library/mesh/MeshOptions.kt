package org.xmtp.android.library.mesh

import android.content.Context
import java.io.File

/**
 * Where a mesh node (the local stand-in for XMTP's servers) keeps its encrypted
 * store: one per inbox on this device ([MeshNodeFiles], D20). Pass the same values to
 * [org.xmtp.android.library.ClientOptions.Api] and [Mesh.start].
 */
class MeshOptions(
    val dbPath: String,
    val encryptionKey: ByteArray,
) {
    init {
        require(encryptionKey.size == 32) { "mesh encryption key must be 32 bytes" }
    }

    internal fun ensureParentDir() {
        File(dbPath).parentFile?.mkdirs()
    }

    override fun toString(): String = "MeshOptions(dbPath=$dbPath)"

    companion object {
        fun inAppFiles(
            context: Context,
            encryptionKey: ByteArray,
        ): MeshOptions =
            MeshOptions(
                File(File(context.filesDir, "xmtp_db"), "xmtp-mesh-node.db3").absolutePath,
                encryptionKey,
            )

        /**
         * The node database for a client of [inboxId] whose libxmtp database lives in
         * [dbDirectory] (the app default when null), per inbox and following that database:
         * a fresh node when it does not exist yet ([MeshNodeFiles.forClient], D20).
         * That fresh node starts with the inbox's identity log, carried with [encryptionKey].
         * Serialize this with client creation and [Mesh.start]/[Mesh.stop] (see [MeshNodeFiles]).
         */
        fun forInbox(
            context: Context,
            inboxId: String,
            encryptionKey: ByteArray,
            dbDirectory: File? = null,
        ): MeshOptions {
            val libxmtpDb =
                MeshNodeFiles.libxmtpDbFile(
                    dbDirectory ?: MeshNodeFiles.defaultDbDirectory(context),
                    inboxId,
                )
            return MeshOptions(
                MeshNodeFiles
                    .forInbox(context, inboxId)
                    .forClient(libxmtpDb, MeshNodeFiles.identityLogCarrier(encryptionKey))
                    .absolutePath,
                encryptionKey,
            )
        }
    }
}
