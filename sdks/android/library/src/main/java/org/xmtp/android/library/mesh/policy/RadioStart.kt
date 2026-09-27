package org.xmtp.android.library.mesh.policy

/** What `MeshRadio.start()` does, decided from plain values so it is testable on the JVM. */
object RadioStart {
    sealed class Decision {
        /** Bring the radio up now. */
        object PowerUp : Decision()

        /** Bluetooth is off: start with `radioUp = false`; the radio comes up when it turns on. */
        object WaitForBluetooth : Decision()

        /** A setup error the host must fix; `start()` throws it. */
        data class Refuse(
            val reason: String,
        ) : Decision()
    }

    fun decide(
        rustMaxFrame: Long,
        linkMaxFrame: Long,
        missingPermissions: List<String>,
        hasAdapter: Boolean,
        bluetoothOn: Boolean,
    ): Decision =
        when {
            rustMaxFrame != linkMaxFrame ->
                Decision.Refuse("frame limit mismatch: xmtp_mesh $rustMaxFrame, link $linkMaxFrame")
            missingPermissions.isNotEmpty() -> Decision.Refuse("missing permissions: $missingPermissions")
            !hasAdapter -> Decision.Refuse("no Bluetooth adapter on this device")
            !bluetoothOn -> Decision.WaitForBluetooth
            else -> Decision.PowerUp
        }

    /** What to do when the platform reports the mesh GATT service add. */
    sealed class ServiceAdded {
        /** Served: start advertising. */
        object Advertise : ServiceAdded()

        /** Not served: power the radio down and retry the start with backoff. */
        data class Restart(
            val reason: String,
        ) : ServiceAdded()
    }

    fun onServiceAdded(ok: Boolean): ServiceAdded =
        if (ok) ServiceAdded.Advertise else ServiceAdded.Restart("mesh GATT service not added; restarting the radio")
}
