package org.xmtp.android.library.mesh

import java.io.File

/**
 * Copies one inbox's identity log from the node database [carry]'s `from` into `to` when
 * [MeshNodeFiles] rotates, so that inbox's next installation extends the log its peers already
 * hold instead of re-creating the inbox (Reset local data; see [MeshNodeFiles.rotate]).
 * Production: [MeshNodeFiles.identityLogCarrier]. Throw on failure; the rotation then continues
 * with an empty node.
 */
fun interface IdentityLogCarrier {
    fun carry(
        from: File,
        to: File,
        inboxId: String,
    )
}
