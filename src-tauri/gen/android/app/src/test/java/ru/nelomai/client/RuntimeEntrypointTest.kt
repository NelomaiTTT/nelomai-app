package ru.nelomai.client

import android.content.Intent
import android.os.ParcelFileDescriptor
import org.junit.Assert.*
import org.junit.Before
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class RuntimeEntrypointTest {
    @Before @After fun freshProcess() = resetRuntimeProcessForTest()
    private val selection = RuntimeSelectionV1("latest", "0.3.3", "0.3.3", 1L, null, "test-incarnation")
    private fun launch() = Intent().putExtra("runtime_selection_v1", RuntimeSelectionStore.encode(selection))

    // These failures must occur before the native library load (unavailable on the JVM)
    // and before the process is pinned to a selection.
    @Test fun missingEndpointIsRejectedBeforeLibraryLoadOrProcessClaim() {
        val failure = runCatching {
            RuntimeEntrypoint.attachFromIntent(launch().putExtra("runtime_bootstrap_v1", "{}"))
        }.exceptionOrNull()
        assertTrue("expected input rejection, got $failure", failure is IllegalArgumentException)
        assertFalse(RuntimeProcessSelection.needsExit(selection.copy(incarnation = "other-incarnation")))
    }

    @Test fun missingBootstrapIsRejectedBeforeLibraryLoadOrProcessClaim() {
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[0].use { endpoint -> pipe[1].use {
            val failure = runCatching {
                RuntimeEntrypoint.attachFromIntent(launch().putExtra("runtime_endpoint_v1", endpoint))
            }.exceptionOrNull()
            assertTrue("expected input rejection, got $failure", failure is IllegalArgumentException)
            assertTrue(endpoint.fileDescriptor.valid())
            assertFalse(RuntimeProcessSelection.needsExit(selection.copy(incarnation = "other-incarnation")))
        } }
    }

    @Test fun oversizedUtf8BootstrapIsRejectedBeforeLibraryLoadOrProcessClaim() {
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[0].use { endpoint -> pipe[1].use {
            val failure = runCatching {
                RuntimeEntrypoint.attachFromIntent(launch().putExtra("runtime_endpoint_v1", endpoint)
                    .putExtra("runtime_bootstrap_v1", "я".repeat(32769)))
            }.exceptionOrNull()
            assertTrue("expected input rejection, got $failure", failure is IllegalArgumentException)
            assertTrue(endpoint.fileDescriptor.valid())
            assertFalse(RuntimeProcessSelection.needsExit(selection.copy(incarnation = "other-incarnation")))
        } }
    }

    @Test fun closedEndpointIsRejectedBeforeLibraryLoadOrProcessClaim() {
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[0].close()
        pipe[1].use {
            val failure = runCatching {
                RuntimeEntrypoint.attachFromIntent(launch().putExtra("runtime_endpoint_v1", pipe[0])
                    .putExtra("runtime_bootstrap_v1", "{}"))
            }.exceptionOrNull()
            assertTrue("expected input rejection, got $failure", failure is IllegalArgumentException)
            assertFalse(RuntimeProcessSelection.needsExit(selection.copy(incarnation = "other-incarnation")))
        }
    }

    @Test fun emptyBootstrapIsRejectedBeforeLibraryLoadOrProcessClaim() {
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[0].use { endpoint -> pipe[1].use {
            val failure = runCatching {
                RuntimeEntrypoint.attachFromIntent(launch().putExtra("runtime_endpoint_v1", endpoint)
                    .putExtra("runtime_bootstrap_v1", ""))
            }.exceptionOrNull()
            assertTrue("expected input rejection, got $failure", failure is IllegalArgumentException)
            assertTrue(endpoint.fileDescriptor.valid())
            assertFalse(RuntimeProcessSelection.needsExit(selection.copy(incarnation = "other-incarnation")))
        } }
    }

    @Test fun invalidSelectionCannotPinProcessBeforeValidation() {
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[0].use { endpoint -> pipe[1].use {
            val failure = runCatching {
                RuntimeEntrypoint.attachFromIntent(launch()
                    .putExtra("runtime_selection_v1", RuntimeSelectionStore.encode(selection.copy(slot = "unknown")))
                    .putExtra("runtime_endpoint_v1", endpoint).putExtra("runtime_bootstrap_v1", "{}"))
            }.exceptionOrNull()
            assertTrue("expected input rejection, got $failure", failure is IllegalArgumentException)
            assertFalse(RuntimeProcessSelection.needsExit(selection))
        } }
    }

    @Test fun missingSelectionCannotClaimProcess() {
        assertTrue(runCatching { RuntimeEntrypoint.attachFromIntent(Intent()) }.exceptionOrNull()
            is IllegalArgumentException)
        assertFalse(RuntimeProcessSelection.needsExit(selection))
    }

    @Test fun alreadyAttachedProcessReopensWithoutConsumedOneShotExtras() {
        // JNI is unavailable in JVM tests. Establish only its successful local latch;
        // exercise the real entrypoint's existing no-second-attach branch.
        val attached = RuntimeEntrypoint::class.java.getDeclaredField("attached").apply { isAccessible = true }
        attached.setBoolean(null, true)
        try {
            RuntimeEntrypoint.attachFromIntent(Intent())
        } finally {
            attached.setBoolean(null, false)
        }
    }
}
