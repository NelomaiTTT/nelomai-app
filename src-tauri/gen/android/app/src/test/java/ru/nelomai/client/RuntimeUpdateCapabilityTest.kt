package ru.nelomai.client

import android.os.Binder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class RuntimeUpdateCapabilityTest {
    @Test fun attachReadsCapabilityWithoutChangingLegacyBootstrapOrEndpoint() {
        for (advertised in listOf(null, 2, 99)) {
            val pair = ParcelFileDescriptor.createSocketPair()
            val store = RuntimeSelectionStore(RuntimeEnvironment.getApplication())
            var registrations = 0
            val remote = object : Binder() {
                override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                    if (code == RuntimeOwnerProtocol.ATTACH + 1) {
                        assertEquals(2, advertised)
                        data.enforceInterface(RuntimeOwnerProtocol.DESCRIPTOR)
                        assertEquals("admitted", data.readString())
                        assertNotNull(data.readStrongBinder())
                        assertEquals(0, data.dataAvail())
                        registrations++
                        reply!!.writeNoException()
                        return true
                    }
                    assertEquals(RuntimeOwnerProtocol.ATTACH, code)
                    data.enforceInterface(RuntimeOwnerProtocol.DESCRIPTOR)
                    assertNotNull(data.readString())
                    assertEquals(0, data.dataAvail())
                    reply!!.writeNoException()
                    reply.writeString("legacy-bootstrap-unchanged")
                    reply.writeParcelable(pair[1], 0)
                    // Like the service, close the sender's copy after parceling.
                    pair[1].close()
                    advertised?.let(reply::writeInt)
                    return true
                }
            }
            RuntimeSelectionStore::class.java.getDeclaredField("remote").apply {
                isAccessible = true; set(store, remote)
            }
            var received: ParcelFileDescriptor? = null
            try {
                val (fd, bootstrap) = store.attach(RuntimeSelectionV1("latest", "0.3.12", "0.3.12", 1L, null, "admitted"))
                received = fd
                assertEquals("legacy-bootstrap-unchanged", bootstrap)
                // The real attach decoder must still return the legacy FD slot.
                // Robolectric does not implement Binder socket duplication.
                assertNotNull(fd)
                val getter = store.javaClass.methods.firstOrNull { it.name == "getUpdateProtocol" }
                assertNotNull("new commands require explicit owner capability", getter)
                assertEquals(if (advertised == 2) 2 else 1, getter!!.invoke(store))
                assertEquals("only an admitted V2 owner gets the Activity probe", if (advertised == 2) 1 else 0, registrations)
            } finally {
                received?.close()
                pair.forEach { it.close() }
                store.close()
            }
        }
    }
}
