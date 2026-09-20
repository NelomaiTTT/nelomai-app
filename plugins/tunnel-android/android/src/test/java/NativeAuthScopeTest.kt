package ru.nelomai.tunnel

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import java.security.cert.Certificate

class NativeAuthScopeTest {
    @Test fun successorWithoutPendingMutationReissuesUsingEffectiveCapability() {
        val cases = listOf(
            Triple(BackgroundCapabilitySnapshot(1, true, 9999999999),
                BackgroundCapabilitySnapshot(2, false, 9999999999), "legacy-token"),
            Triple(BackgroundCapabilitySnapshot(2, false, 9999999999),
                BackgroundCapabilitySnapshot(1, true, 9999999999), "legacy-token"),
            Triple(BackgroundCapabilitySnapshot(1, true, 9999999999),
                BackgroundCapabilitySnapshot(1, false, 9999999999), "legacy-token"),
            Triple(BackgroundCapabilitySnapshot(1, true, 100),
                BackgroundCapabilitySnapshot(1, true, 9999999999), "legacy-token"),
            Triple(BackgroundCapabilitySnapshot(1, true, 9999999999),
                BackgroundCapabilitySnapshot(1, true, 9999999999), "two-phase-token"),
        )
        for ((storedCapability, requestedCapability, expectedToken) in cases) {
            val store = BackgroundCredentialStore(MemoryBackend())
            val old = operation(epoch = 3)
            var current = store.beginOwnerOperation(0, old, false).value()
            current = store.configure(current.revision, BackgroundCredentialProvision(old.scope.deviceId,
                "https://synthetic.invalid", "old-token", 9999999999, "install", 1,
                storedCapability)).value()
            val mode = NativeBackgroundProvisionPolicy.mode(true, true, false, true, true,
                storedCapability.enabled && storedCapability.expiresAtUnix > 100,
                storedCapability == requestedCapability, requestedCapability.enabled)
            val next = old.copy(attempt = 2, scope = old.scope.copy(sessionGeneration = 8))
            val request = BackgroundUiProvisionRequest(current.revision, old.scope.deviceId,
                "https://synthetic.invalid", "new-bearer", "install", 1, requestedCapability, next.scope)
            current = store.beginProvisionOperation(request, next).value()
            val saved = store.withOwnerOperation(next) {
                provisionOwnedBackgroundCredential(store, request.copy(expectedRevision = current.revision),
                    mode, 100, provision = { scoped ->
                        provisionBackgroundCredential(store, scoped, 100,
                            operationIds = { "new-prepare" to "new-activate" },
                            prepare = { credential, prepareId, activateId, _ ->
                                assertEquals("new-bearer", credential.token)
                                BackgroundPendingToken("two-phase-token", 3000, 2, prepareId, activateId, 1)
                            }, activate = { _, token, _ -> BackgroundActivationResult(token.tokenGeneration, 2000) })
                    }, rotate = { error("predecessor token must not rotate") },
                    legacy = { credential ->
                        assertEquals("new-bearer", credential.token)
                        BackgroundCredential(old.scope.deviceId, request.panelBase, "legacy-token", 2000)
                    })
            }
            assertEquals("stored=$storedCapability requested=$requestedCapability", expectedToken, saved.active?.token)
            assertEquals(2000L, saved.active?.expiresAtUnix)
            assertFalse(saved.requiresFreshProvision)
            assertNull(saved.pending)
            assertNull(saved.reservation)
            assertEquals(saved, store.read().value())
        }
    }

    @Test fun roundtripReprovisionsRetainedLatestScopeWithinTheSameLoginFamily() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val old = operation(epoch = 3)
        var current = store.beginOwnerOperation(0, old, false).value()
        current = store.configure(current.revision, BackgroundCredentialProvision(old.scope.deviceId,
            "https://synthetic.invalid", "old-token", 9999999999, "install", 1,
            BackgroundCapabilitySnapshot(0, false, 1))).value()
        // Broker keeps the login family across latest(7) -> stable(8) -> latest(9).
        val next = old.copy(attempt = 3, scope = old.scope.copy(sessionGeneration = 9),
            provisionPredecessor = old.scope.copy(slot = "stable", sessionGeneration = 8))
        val request = BackgroundUiProvisionRequest(current.revision, old.scope.deviceId,
            "https://synthetic.invalid", "bearer", "install", 1,
            BackgroundCapabilitySnapshot(0, false, 1), next.scope)
        val admitted = store.beginProvisionOperation(request, next)
        assertTrue("roundtrip rejected: $admitted", admitted is CredentialStoreResult.Success)
        assertEquals(next.scope, admitted.value().ownerScope)
        assertEquals(1L, admitted.value().active?.expiresAtUnix)
    }

    @Test fun historicalRoundtripReissuesRetainedTokenWithCurrentBearerAfterRestart() {
        for ((recoveryEnabled, currentFamily) in listOf(false to "current-family", true to "stable-family")) {
            val backend = MemoryBackend()
            var store = BackgroundCredentialStore(backend)
            val old = operation().let { it.copy(scope = it.scope.copy(
                slot = "latest", runtimeVersion = "0.3.0", sessionGeneration = 8)) }
            val capability = BackgroundCapabilitySnapshot(1, recoveryEnabled, 9999999999)
            var current = store.beginOwnerOperation(0, old, false).value()
            current = store.configure(current.revision, BackgroundCredentialProvision(old.scope.deviceId,
                "https://synthetic.invalid", "revoked-latest-token", 9999999999, "install", 1, capability)).value()
            // The retained latest namespace predates the immediate stable predecessor.
            val stable = old.scope.copy(family = "stable-family", slot = "stable",
                runtimeVersion = "0.2.20", sessionGeneration = 9)
            val next = NativeOwnerOperation.fromJson(old.copy(attempt = 3,
                scope = old.scope.copy(family = currentFamily, sessionGeneration = 10),
                provisionPredecessor = stable).toJson())
            val request = BackgroundUiProvisionRequest(current.revision, old.scope.deviceId,
                "https://synthetic.invalid", "current-bearer", "install", 1, capability, next.scope)
            val admitted = store.beginProvisionOperation(request, next)
            assertTrue("historical roundtrip rejected: $admitted", admitted is CredentialStoreResult.Success)
            assertEquals(1L, admitted.value().active?.expiresAtUnix)
            store = BackgroundCredentialStore(backend)
            assertTrue(store.read().value().requiresFreshProvision)
            // An issuance failure must leave the old token expired and a retry
            // must still issue with the bearer, not rotate/adopt the old token.
            try {
                store.withOwnerOperation(next) {
                    provisionOwnedBackgroundCredential(store, request.copy(expectedRevision = admitted.value().revision),
                        "noop", 100, provision = { throw BackgroundConnectionException("test_network_error") },
                        rotate = { error("revoked token cannot rotate") },
                        legacy = { throw BackgroundConnectionException("test_network_error") })
                }
                fail("issuance failure swallowed")
            } catch (error: BackgroundConnectionException) {
                assertEquals("test_network_error", error.code)
            }
            assertEquals(admitted.value(), store.read().value())
            var issued = 0
            val saved = store.withOwnerOperation(next) {
                provisionOwnedBackgroundCredential(store, request.copy(expectedRevision = admitted.value().revision),
                    "noop", 100, provision = { scoped ->
                        provisionBackgroundCredential(store, scoped, 100,
                            operationIds = { "prepare-current" to "activate-current" },
                            prepare = { credential, prepareId, activateId, _ ->
                                issued++
                                assertEquals("current-bearer", credential.token)
                                assertEquals(next.scope, credential.ownerScope)
                                BackgroundPendingToken("new-token", 3000, 2, prepareId, activateId, 1)
                            }, activate = { _, token, _ -> BackgroundActivationResult(token.tokenGeneration, 2000) })
                    }, rotate = { error("revoked token cannot rotate") }, legacy = { credential ->
                        issued++
                        assertEquals("current-bearer", credential.token)
                        assertEquals(next.scope, credential.ownerScope)
                        BackgroundCredential(old.scope.deviceId, request.panelBase, "new-token", 2000)
                    })
            }
            assertEquals(1, issued)
            assertEquals("new-token", saved.active?.token)
            assertEquals(next.scope, saved.ownerScope)
            assertFalse(saved.requiresFreshProvision)
            assertTrue(store.beginOwnerOperation(saved.revision, old, true) is CredentialStoreResult.Failure)
            assertEquals(saved, store.read().value())
        }
    }

    @Test fun retainedRoundtripCannotBypassProvisionOrOwnerFences() {
        for (boundary in listOf("no_proof", "proof_epoch", "proof_device", "proof_old", "proof_future", "proof_gap",
                "same_slot", "other_runtime", "other_contract", "epoch", "device", "generation",
                "install", "panel", "logout", "recovery", "expired", "old_attempt", "no_bearer")) {
            val store = BackgroundCredentialStore(MemoryBackend(), nowMillis = { 1000L })
            val old = operation().let { it.copy(scope = it.scope.copy(
                slot = "latest", runtimeVersion = "0.3.0", sessionGeneration = 8)) }
            var current = store.beginOwnerOperation(0, old, false).value()
            current = store.configure(current.revision, BackgroundCredentialProvision(old.scope.deviceId,
                "https://synthetic.invalid", "old-token", 9999999999, "install", 1,
                BackgroundCapabilitySnapshot(0, false, 1))).value()
            if (boundary == "logout") current = store.fenceOwnerLogout(4).value()
            val otherDevice = "99999999-9999-4999-8999-999999999999"
            val proof = old.scope.copy(family = "stable-family", slot = if (boundary == "same_slot") "latest" else "stable",
                runtimeVersion = "0.2.20", authEpoch = if (boundary == "proof_epoch") 4 else 3,
                deviceId = if (boundary == "proof_device") otherDevice else old.scope.deviceId,
                sessionGeneration = when (boundary) { "proof_old" -> 8; "proof_future" -> 10; else -> 9 })
            val next = old.copy(attempt = if (boundary == "old_attempt") 1 else 3,
                expiresAtUnixMs = if (boundary == "expired") 1000 else 999999,
                scope = old.scope.copy(family = "current-family", authEpoch = if (boundary == "epoch") 4 else 3,
                    deviceId = if (boundary == "device") otherDevice else old.scope.deviceId,
                    runtimeVersion = if (boundary == "other_runtime") "0.4.0" else "0.3.0",
                    runtimeContractVersion = if (boundary == "other_contract") 2 else old.scope.runtimeContractVersion,
                    sessionGeneration = when (boundary) { "generation" -> 8; "proof_gap" -> 11; else -> 10 }),
                provisionPredecessor = if (boundary == "no_proof") null else proof)
            val request = BackgroundUiProvisionRequest(current.revision, next.scope.deviceId,
                if (boundary == "panel") "https://other.invalid" else "https://synthetic.invalid",
                if (boundary == "no_bearer") "" else "bearer", if (boundary == "install") "other" else "install",
                1, BackgroundCapabilitySnapshot(0, false, 1), next.scope)
            val result = if (boundary == "recovery") store.beginOwnerOperation(current.revision, next, true)
                else store.beginProvisionOperation(request, next)
            assertTrue("admitted $boundary", result is CredentialStoreResult.Failure)
            assertEquals("mutated $boundary", current, store.read().value())
        }
    }

    @Test fun appliedOldActivationMustBeSettledThenReissuedForSuccessorEvenAfterRestart() {
        for ((restartAfterOldAck, historicalRoundtrip) in listOf(false to false, true to false, false to true, true to true)) {
            val backend = MemoryBackend()
            var store = BackgroundCredentialStore(backend)
            val old = operation(epoch = 3)
            var current = store.beginOwnerOperation(0, old, false).value()
            current = store.configure(current.revision, BackgroundCredentialProvision(old.scope.deviceId,
                "https://synthetic.invalid", "old-active", 9999999999, "install", 1,
                BackgroundCapabilitySnapshot(1, true, 9999999999))).value()
            current = store.reserveMutation(current.revision, "old-prepare", old.scope.deviceId,
                1000, 100, "old-activate").value()
            current = store.savePendingToken(current.revision, "old-prepare",
                BackgroundPendingToken("old-applied", 2000, 2, "old-prepare", "old-activate", 1), 100).value()
            val next = if (historicalRoundtrip) old.copy(attempt = 3,
                scope = old.scope.copy(family = "current-family", sessionGeneration = 9),
                provisionPredecessor = old.scope.copy(slot = "latest", family = "other-slot-family", sessionGeneration = 8))
            else old.copy(attempt = 2, scope = old.scope.copy(sessionGeneration = 8))
            val request = BackgroundUiProvisionRequest(current.revision, old.scope.deviceId,
                "https://synthetic.invalid", "new-bearer", "install", 1,
                BackgroundCapabilitySnapshot(1, true, 9999999999), next.scope)
            current = store.beginProvisionOperation(request, next).value()
            if (restartAfterOldAck) {
                // APPLIED replay may acknowledge a token invalidated by runtime/resume.
                current = store.withOwnerOperation(next) {
                    store.promotePending(current.revision, "old-activate", 2000).value()
                }
                assertEquals(1L, current.active?.expiresAtUnix)
                store = BackgroundCredentialStore(backend)
            }
            var freshIssues = 0
            val saved = store.withOwnerOperation(next) {
                provisionOwnedBackgroundCredential(store, request.copy(expectedRevision = current.revision),
                    "noop", 100, provision = { scoped ->
                        provisionBackgroundCredential(store, scoped, 100,
                            operationIds = { "new-prepare" to "new-activate" },
                            prepare = { _, prepareId, activateId, _ ->
                                freshIssues++
                                BackgroundPendingToken("new-token", 3000, 3, prepareId, activateId, 1)
                            }, activate = { _, token, _ -> BackgroundActivationResult(token.tokenGeneration, 2000) })
                    }, rotate = { error("must issue via bearer") }, legacy = { error("recovery enabled") })
            }
            assertEquals(1, freshIssues)
            assertEquals("new-token", saved.active?.token)
            assertEquals(2000L, saved.active?.expiresAtUnix)
        }
    }

    @Test fun confirmedPredecessorCannotBypassDeviceEpochGenerationOrLogoutFences() {
        for (boundary in listOf("missing_proof", "wrong_predecessor", "epoch", "device",
                "generation", "install", "panel", "logout", "recovery", "expired", "old_attempt")) {
            val store = BackgroundCredentialStore(MemoryBackend(), nowMillis = { 1000L })
            val old = operation(epoch = 3)
            var current = store.beginOwnerOperation(0, old, false).value()
            current = store.configure(current.revision, BackgroundCredentialProvision(
                old.scope.deviceId, "https://synthetic.invalid", "old-token", 9999999999,
                "install", 1, BackgroundCapabilitySnapshot(0, false, 1),
            )).value()
            if (boundary == "logout") current = store.fenceOwnerLogout(4).value()
            val nextScope = old.scope.copy(family = "resumed-family",
                authEpoch = if (boundary == "epoch") 4 else 3,
                deviceId = if (boundary == "device") "99999999-9999-4999-8999-999999999999" else old.scope.deviceId,
                sessionGeneration = if (boundary == "generation") 7 else 8)
            val wire = old.copy(scope = nextScope,
                attempt = if (boundary == "old_attempt") 1 else 2,
                expiresAtUnixMs = if (boundary == "expired") 1000 else 999999).toJson()
            if (boundary != "missing_proof") wire.put("provision_predecessor",
                old.scope.copy(family = if (boundary == "wrong_predecessor") "foreign" else old.scope.family).toJson())
            val next = NativeOwnerOperation.fromJson(wire)
            val request = BackgroundUiProvisionRequest(current.revision, next.scope.deviceId,
                if (boundary == "panel") "https://other.invalid" else "https://synthetic.invalid",
                "bearer", if (boundary == "install") "other-install" else "install", 1,
                BackgroundCapabilitySnapshot(0, false, 1), next.scope)
            val result = if (boundary == "recovery") {
                store.beginOwnerOperation(current.revision, next, true)
            } else store.beginProvisionOperation(request, next)
            assertTrue("admitted $boundary", result is CredentialStoreResult.Failure)
            assertEquals("mutated $boundary", current, store.read().value())
        }
    }

    @Test fun ownerConfirmedFamilyTransitionReissuesTokenAndRejectsOldOwner() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val predecessor = operation(epoch = 3)
        var current = store.beginOwnerOperation(0, predecessor, false).value()
        current = store.configure(current.revision, BackgroundCredentialProvision(
            predecessor.scope.deviceId, "https://synthetic.invalid", "old-token",
            9999999999, "install", 1, BackgroundCapabilitySnapshot(0, false, 1),
        )).value()
        val successor = operation(attempt = 2, epoch = 3).let {
            val wire = it.copy(scope = it.scope.copy(family = "resumed-family",
                runtimeVersion = "0.3.0", sessionGeneration = 8)).toJson()
            wire.put("provision_predecessor", predecessor.scope.toJson())
            NativeOwnerOperation.fromJson(wire)
        }
        val request = BackgroundUiProvisionRequest(current.revision, successor.scope.deviceId,
            "https://synthetic.invalid", "bearer", "install", 1,
            BackgroundCapabilitySnapshot(0, false, 1), successor.scope)
        val admission = store.beginProvisionOperation(request, successor)
        assertTrue("owner-confirmed successor rejected: $admission", admission is CredentialStoreResult.Success)
        val begun = admission.value()
        // The trusted wire proof must survive a process/store round-trip too.
        assertEquals(predecessor.scope.toJson().toString(),
            NativeOwnerOperation.fromJson(successor.toJson()).toJson()
                .getJSONObject("provision_predecessor").toString())
        var issued = 0
        val saved = store.withOwnerOperation(successor) {
            provisionOwnedBackgroundCredential(store, request.copy(expectedRevision = begun.revision),
                "noop", 100, provision = { error("disabled recovery") },
                rotate = { error("old family token cannot rotate") },
                legacy = { issued++; BackgroundCredential(successor.scope.deviceId,
                    request.panelBase, "new-token", 1000) })
        }
        assertEquals(1, issued)
        assertEquals("new-token", saved.active?.token)
        assertEquals(successor.scope, saved.ownerScope)
        assertTrue(store.beginOwnerOperation(saved.revision, predecessor, true) is CredentialStoreResult.Failure)
        assertEquals(saved, store.read().value())
        assertTrue(store.beginProvisionOperation(request.copy(expectedRevision = saved.revision), successor)
            is CredentialStoreResult.Success)
    }

    @Test fun provisionAdoptsOnlyMatchingUnscopedLegacyCredentials() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val owner = operation()
        val legacy = BackgroundCredential(owner.scope.deviceId, "https://synthetic.invalid", "legacy", 1000)
        val imported = store.importLegacy(legacy).value()
        val request = BackgroundUiProvisionRequest(imported.revision, owner.scope.deviceId,
            legacy.panelBase, "bearer", "install", 1, BackgroundCapabilitySnapshot(0, false, 1), owner.scope)
        assertTrue(store.beginOwnerOperation(imported.revision, owner, false) is CredentialStoreResult.Failure)
        val adopted = store.beginProvisionOperation(request, owner).value()
        assertEquals(owner.scope, adopted.ownerScope)
        assertEquals("legacy", adopted.active?.token)
        assertEquals(owner, adopted.ownerOperation)
        assertTrue(store.beginProvisionOperation(request, owner) is CredentialStoreResult.Failure)
    }

    @Test fun adoptedLegacyTokenIsReissuedEvenIfPreviouslyReportedFreshAndNoop() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val owner = operation()
        val old = store.configure(0, BackgroundCredentialProvision(owner.scope.deviceId,
            "https://synthetic.invalid", "old-token", 9999999999, "install", 1,
            BackgroundCapabilitySnapshot(0, false, 1))).value()
        val request = BackgroundUiProvisionRequest(old.revision, owner.scope.deviceId,
            "https://synthetic.invalid", "bearer", "install", 1,
            BackgroundCapabilitySnapshot(0, false, 1), owner.scope)
        val begun = store.beginProvisionOperation(request, owner).value()
        var issued = 0
        val saved = store.withOwnerOperation(owner) {
            provisionOwnedBackgroundCredential(store, request.copy(expectedRevision = begun.revision), "noop", 100,
                provision = { error("disabled capability") }, rotate = { error("old scope must use bearer") },
                legacy = { issued++; BackgroundCredential(owner.scope.deviceId, request.panelBase, "new-token", 1000) })
        }
        assertEquals(1, issued)
        assertEquals("new-token", saved.active?.token)
    }

    @Test fun authenticatedSuccessorRuntimeAdoptsCredentialAndReissuesToken() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val predecessor = operation(epoch = 3)
        var current = store.beginOwnerOperation(0, predecessor, false).value()
        current = store.configure(current.revision, BackgroundCredentialProvision(
            predecessor.scope.deviceId, "https://synthetic.invalid", "predecessor-token",
            9999999999, "synthetic-install", 1,
            BackgroundCapabilitySnapshot(0, false, 1),
        )).value()
        val successor = operation(attempt = 2, epoch = 3).let { operation ->
            operation.copy(scope = operation.scope.copy(
                slot = "latest",
                containerVersion = "0.3.0",
                runtimeVersion = "0.3.0",
                sessionGeneration = 8,
            ))
        }
        val request = BackgroundUiProvisionRequest(
            current.revision, successor.scope.deviceId, "https://synthetic.invalid",
            "successor-access", "synthetic-install", 1,
            BackgroundCapabilitySnapshot(0, false, 1), successor.scope,
        )

        val begun = store.beginProvisionOperation(request, successor).value()
        var issued = 0
        val saved = store.withOwnerOperation(successor) {
            provisionOwnedBackgroundCredential(
                store, request.copy(expectedRevision = begun.revision), "noop", 100,
                provision = { error("disabled capability must use bearer issuance") },
                rotate = { error("predecessor token must not rotate under successor scope") },
                legacy = {
                    issued++
                    BackgroundCredential(
                        successor.scope.deviceId,
                        request.panelBase,
                        "successor-token",
                        1000,
                    )
                },
            )
        }

        assertEquals(1, issued)
        assertEquals(successor.scope, saved.ownerScope)
        assertEquals("successor-token", saved.active?.token)
        assertEquals(1000L, saved.active?.expiresAtUnix)
    }

    @Test fun successorRuntimeProvisionRemainsUsableByQuickTileRecoveryStart() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val predecessor = operation(epoch = 3)
        var current = store.beginOwnerOperation(0, predecessor, false).value()
        current = store.configure(current.revision, BackgroundCredentialProvision(
            predecessor.scope.deviceId, "https://synthetic.invalid", "predecessor-token",
            9999999999, "synthetic-install", 1,
            BackgroundCapabilitySnapshot(0, false, 1),
        )).value()
        val successor = operation(attempt = 2, epoch = 3).let { operation ->
            operation.copy(scope = operation.scope.copy(
                slot = "latest",
                containerVersion = "0.3.0",
                runtimeVersion = "0.3.0",
                sessionGeneration = 8,
            ))
        }
        val request = BackgroundUiProvisionRequest(
            current.revision, successor.scope.deviceId, "https://synthetic.invalid",
            "successor-access", "synthetic-install", 1,
            BackgroundCapabilitySnapshot(0, false, 1), successor.scope,
        )

        val begun = store.beginProvisionOperation(request, successor).value()
        val saved = store.withOwnerOperation(successor) {
            provisionOwnedBackgroundCredential(
                store, request.copy(expectedRevision = begun.revision), "noop", 100,
                provision = { error("disabled capability must use bearer issuance") },
                rotate = { error("predecessor token must not rotate under successor scope") },
                legacy = {
                    BackgroundCredential(
                        successor.scope.deviceId,
                        request.panelBase,
                        "successor-token",
                        1000,
                    )
                },
            )
        }
        assertEquals("successor-token", saved.active?.token)

        val policy = selectQuickStartPolicy(
            store = store,
            template = AndroidIntentTemplate(
                deviceId = successor.scope.deviceId,
                accountScope = "account-1",
                layer = "stray",
                ticConnectionMode = "dynamic",
                routeMode = "standalone",
                egressMode = "ipv4",
                allowAlternate = true,
            ),
            nowUnix = 100,
            fetch = {
                BackgroundCapabilitySnapshot(
                    revision = 1,
                    enabled = true,
                    expiresAtUnix = 2000,
                    reserveEnabled = true,
                )
            },
        )
        val dispatch = AndroidConnectionIntentDispatchState()
        val selected = dispatch.toggle(
            expectedGeneration = 0,
            durableDesiredActive = false,
        ) as AndroidQuickToggleDispatch.Start
        var recoveryStarts = 0
        var legacyStarts = 0

        val result = executeDispatchedQuickStart(
            dispatch = dispatch,
            start = selected,
            selectPolicy = { policy },
            recoveryStart = {
                recoveryStarts += 1
                AndroidCoordinatorResult.Accepted(AndroidRecoveryEnvelope.empty(1))
            },
            legacyStart = { legacyStarts += 1 },
        )

        assertTrue(result is AndroidQuickStartExecution.RecoveryAccepted)
        assertEquals(1, recoveryStarts)
        assertEquals(0, legacyStarts)
    }

    @Test fun successorRuntimeAcceptsACompletedCredentialRotation() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val predecessor = operation(epoch = 3)
        var current = store.beginOwnerOperation(0, predecessor, false).value()
        current = store.configure(current.revision, BackgroundCredentialProvision(
            predecessor.scope.deviceId, "https://synthetic.invalid", "predecessor-token",
            1000, "synthetic-install", 1,
            BackgroundCapabilitySnapshot(1, true, 2000),
        )).value()
        current = store.reserveMutation(
            current.revision,
            "prepare",
            predecessor.scope.deviceId,
            1500,
            100,
            "activate",
        ).value()
        current = store.savePendingToken(
            current.revision,
            "prepare",
            BackgroundPendingToken("rotated-token", 1500, 2, "prepare", "activate", 1),
            100,
        ).value()
        current = store.promotePending(current.revision, "activate", 1500).value()
        assertNotNull(current.previous)

        val successor = operation(attempt = 2, epoch = 3).let { operation ->
            operation.copy(scope = operation.scope.copy(
                slot = "latest",
                containerVersion = "0.3.0",
                runtimeVersion = "0.3.0",
                sessionGeneration = 8,
            ))
        }
        val request = BackgroundUiProvisionRequest(
            current.revision, successor.scope.deviceId, "https://synthetic.invalid",
            "successor-access", "synthetic-install", 1,
            BackgroundCapabilitySnapshot(1, true, 2000), successor.scope,
        )

        assertTrue(
            store.beginProvisionOperation(request, successor) is CredentialStoreResult.Success,
        )
    }

    @Test fun successorRuntimeAdoptionRejectsDifferentAuthorityOrNonIncreasingGeneration() {
        val predecessor = operation(epoch = 3)
        val validSuccessor = operation(attempt = 2, epoch = 3).scope.copy(
            runtimeVersion = "0.3.0",
            sessionGeneration = 8,
        )
        val variants = listOf(
            Triple(operation(attempt = 2, epoch = 4).scope.copy(sessionGeneration = 8),
                "https://synthetic.invalid", "synthetic-install"),
            Triple(operation(attempt = 2, epoch = 3).scope.copy(
                family = "other-family", sessionGeneration = 8),
                "https://synthetic.invalid", "synthetic-install"),
            Triple(operation(attempt = 2, epoch = 3).scope.copy(
                deviceId = "33333333-3333-4333-8333-333333333333",
                sessionGeneration = 8,
            ), "https://synthetic.invalid", "synthetic-install"),
            Triple(operation(attempt = 2, epoch = 3).scope.copy(
                runtimeVersion = "0.3.0",
                sessionGeneration = 7,
            ), "https://synthetic.invalid", "synthetic-install"),
            Triple(operation(attempt = 2, epoch = 3).scope.copy(
                runtimeVersion = "0.3.0",
                sessionGeneration = 6,
            ), "https://synthetic.invalid", "synthetic-install"),
            Triple(validSuccessor, "https://other.invalid", "synthetic-install"),
            Triple(validSuccessor, "https://synthetic.invalid", "other-install"),
        )
        for ((scope, panelBase, installSecret) in variants) {
            val store = BackgroundCredentialStore(MemoryBackend())
            var current = store.beginOwnerOperation(0, predecessor, false).value()
            current = store.configure(current.revision, BackgroundCredentialProvision(
                predecessor.scope.deviceId, "https://synthetic.invalid", "predecessor-token",
                9999999999, "synthetic-install", 1,
                BackgroundCapabilitySnapshot(0, false, 1),
            )).value()
            val successor = operation(attempt = 2, epoch = scope.authEpoch).copy(scope = scope)
            val request = BackgroundUiProvisionRequest(
                current.revision, successor.scope.deviceId, panelBase,
                "successor-access", installSecret, 1,
                BackgroundCapabilitySnapshot(0, false, 1), successor.scope,
            )

            assertTrue(store.beginProvisionOperation(request, successor) is CredentialStoreResult.Failure)
            assertEquals(current, store.read().value())
        }
    }

    @Test fun successorRuntimeFinishesUnfinishedMutationAfterCapabilityIsDisabled() {
        for (pendingExists in listOf(false, true)) {
            val store = BackgroundCredentialStore(MemoryBackend())
            val predecessor = operation(epoch = 3)
            var current = store.beginOwnerOperation(0, predecessor, false).value()
            current = store.configure(current.revision, BackgroundCredentialProvision(
                predecessor.scope.deviceId, "https://synthetic.invalid", "predecessor-token",
                9999999999, "synthetic-install", 1,
                BackgroundCapabilitySnapshot(1, true, 9999999999),
            )).value()
            current = store.reserveMutation(
                current.revision,
                "predecessor-prepare",
                predecessor.scope.deviceId,
                1000,
                100,
                "predecessor-activate",
            ).value()
            if (pendingExists) {
                current = store.savePendingToken(
                    current.revision,
                    "predecessor-prepare",
                    BackgroundPendingToken(
                        "predecessor-pending", 2000, 2,
                        "predecessor-prepare", "predecessor-activate", 1,
                    ),
                    100,
                ).value()
            }
            val successor = operation(attempt = 2, epoch = 3).let { operation ->
                operation.copy(scope = operation.scope.copy(
                    containerVersion = "0.3.0",
                    runtimeVersion = "0.3.0",
                    sessionGeneration = 8,
                ))
            }
            val request = BackgroundUiProvisionRequest(
                current.revision, successor.scope.deviceId, "https://synthetic.invalid",
                "successor-access", "synthetic-install", 1,
                BackgroundCapabilitySnapshot(2, false, 1), successor.scope,
            )

            val admitted = store.beginProvisionOperation(request, successor).value()
            var prepared = 0
            var activated = 0
            var legacyCalls = 0
            val saved = store.withOwnerOperation(successor) {
                provisionOwnedBackgroundCredential(
                    store, request.copy(expectedRevision = admitted.revision), "two_phase", 100,
                    provision = { scoped ->
                        provisionBackgroundCredential(
                            store, scoped, 100,
                            operationIds = { error("existing operation IDs must be retained") },
                            prepare = { _, prepareId, activationId, _ ->
                                prepared++
                                BackgroundPendingToken(
                                    "successor-pending", 2000, 2,
                                    prepareId, activationId, 1,
                                )
                            },
                            activate = { _, token, _ ->
                                activated++
                                BackgroundActivationResult(token.tokenGeneration, 2000)
                            },
                        )
                    },
                    rotate = { error("unfinished mutation must have priority") },
                    legacy = {
                        legacyCalls++
                        BackgroundCredential(
                            successor.scope.deviceId,
                            request.panelBase,
                            "successor-legacy",
                            2000,
                        )
                    },
                )
            }

            assertEquals(0, prepared)
            assertEquals(if (pendingExists) 1 else 0, activated)
            assertEquals(1, legacyCalls)
            assertEquals("successor-legacy", saved.active?.token)
            assertFalse(saved.capability?.enabled ?: true)
            assertEquals(successor.scope, saved.ownerScope)
            assertNull(saved.pending)
            assertNull(saved.reservation)
        }
    }

    @Test fun successorRuntimeCanRetryLegacyAfterDisabledPendingActivationIsDiscarded() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val predecessor = operation(epoch = 3)
        var current = store.beginOwnerOperation(0, predecessor, false).value()
        current = store.configure(current.revision, BackgroundCredentialProvision(
            predecessor.scope.deviceId, "https://synthetic.invalid", "predecessor-token",
            9999999999, "synthetic-install", 1,
            BackgroundCapabilitySnapshot(1, true, 9999999999),
        )).value()
        current = store.reserveMutation(
            current.revision,
            "predecessor-prepare",
            predecessor.scope.deviceId,
            1000,
            100,
            "predecessor-activate",
        ).value()
        current = store.savePendingToken(
            current.revision,
            "predecessor-prepare",
            BackgroundPendingToken(
                "predecessor-pending", 2000, 2,
                "predecessor-prepare", "predecessor-activate", 1,
            ),
            100,
        ).value()
        val successor = operation(attempt = 2, epoch = 3).let { operation ->
            operation.copy(scope = operation.scope.copy(
                containerVersion = "0.3.0",
                runtimeVersion = "0.3.0",
                sessionGeneration = 8,
            ))
        }
        var request = BackgroundUiProvisionRequest(
            current.revision, successor.scope.deviceId, "https://synthetic.invalid",
            "successor-access", "synthetic-install", 1,
            BackgroundCapabilitySnapshot(2, false, 1), successor.scope,
        )

        val admitted = store.beginProvisionOperation(request, successor).value()
        request = request.copy(expectedRevision = admitted.revision)
        try {
            store.withOwnerOperation(successor) {
                provisionOwnedBackgroundCredential(
                    store, request, "two_phase", 100,
                    provision = { scoped ->
                        provisionBackgroundCredential(
                            store, scoped, 100,
                            operationIds = { error("existing pending token must be reused") },
                            prepare = { _, _, _, _ -> error("existing pending token must be reused") },
                            activate = { _, _, _ ->
                                throw BackgroundConnectionException("activation_not_applied")
                            },
                        )
                    },
                    rotate = { error("pending activation must have priority") },
                    legacy = { error("authoritative discard must surface before fallback") },
                )
            }
            fail("authoritative activation result must be surfaced")
        } catch (error: BackgroundConnectionException) {
            assertEquals("activation_not_applied", error.code)
        }

        current = store.read().value()
        assertFalse(current.capability?.enabled ?: true)
        assertNull(current.pending)
        assertNull(current.reservation)

        val retried = store.withOwnerOperation(successor) {
            provisionOwnedBackgroundCredential(
                store, request.copy(expectedRevision = current.revision), "legacy", 100,
                provision = { error("disabled capability must use legacy issuance") },
                rotate = { error("discarded pending token must not rotate") },
                legacy = {
                    BackgroundCredential(
                        successor.scope.deviceId,
                        request.panelBase,
                        "successor-legacy",
                        2000,
                    )
                },
            )
        }

        assertEquals("successor-legacy", retried.active?.token)
        assertEquals(successor.scope, retried.ownerScope)
        assertNull(retried.pending)
        assertNull(retried.reservation)
    }

    @Test fun legacyProvisionRejectsOtherDevicePanelAndCancelledOwnerWithoutChangingRecord() {
        for (variant in 0..3) {
            val store = BackgroundCredentialStore(MemoryBackend())
            val owner = operation()
            var saved = store.importLegacy(BackgroundCredential(owner.scope.deviceId,
                "https://synthetic.invalid", "legacy", 1000)).value()
            if (variant == 3) saved = store.fenceOwnerLogout(owner.scope.authEpoch).value()
            val request = BackgroundUiProvisionRequest(saved.revision,
                if (variant == 0) "33333333-3333-4333-8333-333333333333" else owner.scope.deviceId,
                if (variant == 1) "https://other.invalid" else "https://synthetic.invalid",
                "bearer", "install", 1, BackgroundCapabilitySnapshot(0, false, 1), owner.scope)
            val ticket = if (variant == 2) owner.copy(expiresAtUnixMs = 1) else owner
            assertTrue(store.beginProvisionOperation(request, ticket) is CredentialStoreResult.Failure)
            assertEquals(saved, store.read().value())
        }
    }
    @Test fun finalizedLegacyLogoutAdmitsFreshOwnerButNotCancelledOwner() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val owner = operation(1, 5)
        store.configure(0, BackgroundCredentialProvision(owner.scope.deviceId, "https://synthetic.invalid",
            "old-background", 1000, "synthetic-install", 1, BackgroundCapabilitySnapshot(0, false, 1))).value()
        store.fenceOwnerLogout(4).value()
        var current = store.beginLogoutCurrent("legacy-logout").value().envelope
        assertTrue(store.beginOwnerOperation(current.revision, owner, false) is CredentialStoreResult.Failure)
        current = store.finalizeLogout(current.revision, "legacy-logout").value()
        assertNull(current.ownerScope)
        assertTrue(store.beginOwnerOperation(current.revision, operation(1, 4), false) is CredentialStoreResult.Failure)
        assertTrue(store.beginOwnerOperation(current.revision, owner, true) is CredentialStoreResult.Failure)
        val admitted = store.beginOwnerOperation(current.revision, owner, false).value()
        assertEquals(owner.scope, admitted.ownerScope)
        assertNull(admitted.cleanupCredential)
    }

    @Test fun rejectedRecoveryAdmissionKeepsOldLogoutAndCredentialsWithoutClaimingAnUnknownHttpOutcome() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val owner = operation()
        store.configure(0, BackgroundCredentialProvision(owner.scope.deviceId, "https://synthetic.invalid",
            "old-background", 1000, "synthetic-install", 1, BackgroundCapabilitySnapshot(0, false, 1))).value()
        store.beginLogoutCurrent("old-logout").value()
        val before = store.read().value()
        try {
            admitBackgroundRecovery(store, owner)
            fail("pending legacy logout must refuse recovery before HTTP")
        } catch (error: BackgroundConnectionException) {
            assertEquals("background_recovery_not_issued", error.code)
        }
        assertEquals(before, store.read().value())
        assertNotNull(before.cleanupCredential)
        assertEquals(BackgroundLogoutPhase.PENDING, before.logoutState?.phase)
    }

    @Test fun admittedRecoveryStillRejectsExpiredCallbacksWithoutReclassifyingTheirOutcome() {
        var now = 1000L
        val store = BackgroundCredentialStore(MemoryBackend(), nowMillis = { now })
        val owner = operation().copy(expiresAtUnixMs = 2000)
        store.beginOwnerOperation(0, owner, false).value()
        val next = operation(2).copy(expiresAtUnixMs = 2000)
        admitBackgroundRecovery(store, next)
        now = 2001
        store.withOwnerOperation(next) {
            assertEquals(CredentialStoreResult.Failure("background_owner_cancelled"), store.read())
        }
    }

    private fun operation(attempt: Long = 1, epoch: Long = 3) = NativeOwnerOperation.fromJson(JSONObject("""
        {"ticket":{"operation_id":"11111111-1111-4111-8111-111111111111","auth_epoch":$epoch,"attempt":$attempt,"family":"synthetic-family","device_id":"22222222-2222-4222-8222-222222222222","identity":{"slot":"stable","container_version":"0.2.16","runtime_version":"0.2.15","runtime_contract_version":1,"session_generation":7}},"expires_at_unix_ms":9999999999999}
    """))

    @Test fun ownerSnapshotHeadersPreserveEveryIdentityField() {
        val scope = operation().scope
        assertEquals(mapOf(
            "X-Nelomai-App-Version" to "0.2.16", "X-Nelomai-Container-Version" to "0.2.16",
            "X-Nelomai-Runtime-Version" to "0.2.15", "X-Nelomai-Runtime-Contract-Version" to "1",
            "X-Nelomai-Runtime-Slot" to "stable", "X-Nelomai-Session-Generation" to "7",
        ), scope.identityHeaders())
        assertEquals(scope, NativeOwnerScope.fromJson(scope.toJson()))
    }

    @Test fun realBearerTransportWritesTheSnapshotHeadersToTheConnection() {
        val connection = object : HttpsURLConnection(URL("https://synthetic.invalid")) {
            override fun connect() {}
            override fun disconnect() {}
            override fun usingProxy() = false
            override fun getCipherSuite() = "synthetic"
            override fun getLocalCertificates(): Array<Certificate>? = null
            override fun getServerCertificates(): Array<Certificate> = emptyArray()
            override fun getResponseCode() = 200
            override fun getInputStream() = "{}".byteInputStream()
        }
        val credential = BackgroundCredential(operation().scope.deviceId, "https://synthetic.invalid", "synthetic-access", 1000, operation().scope)
        val transport = UrlConnectionBackgroundApiTransport { url ->
            assertEquals("/api/client/v1/background/token", url.path)
            connection
        }
        transport.execute(credential, "POST", "background/token", null, BackgroundAuthorization.BEARER)
        assertEquals("Bearer synthetic-access", connection.getRequestProperty("Authorization"))
        assertEquals("0.2.16", connection.getRequestProperty("X-Nelomai-App-Version"))
        assertEquals("0.2.16", connection.getRequestProperty("X-Nelomai-Container-Version"))
        assertEquals("0.2.15", connection.getRequestProperty("X-Nelomai-Runtime-Version"))
        assertEquals("1", connection.getRequestProperty("X-Nelomai-Runtime-Contract-Version"))
        assertEquals("stable", connection.getRequestProperty("X-Nelomai-Runtime-Slot"))
        assertEquals("7", connection.getRequestProperty("X-Nelomai-Session-Generation"))
    }

    @Test fun newerOwnerOperationFencesOldNativeWritesWithoutErasingScope() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val first = operation()
        val begun = store.beginOwnerOperation(0, first, false).value()
        val second = operation(2)
        val replaced = store.beginOwnerOperation(begun.revision, second, false).value()
        store.withOwnerOperation(first) {
            assertTrue(store.updateCapability(replaced.revision, BackgroundCapabilitySnapshot(1, true, 9999999999)) is CredentialStoreResult.Failure)
        }
        assertEquals(replaced, store.read().value())
        store.cancelOwnerOperation(second).value()
        store.withOwnerOperation(second) {
            assertTrue(store.read() is CredentialStoreResult.Failure)
        }
        assertEquals(second.scope, store.read().value().ownerScope)
    }

    @Test fun missingProtectedRecordCannotTurnAnOldCallbackIntoFreshInitialization() {
        val backend = MemoryBackend()
        val store = BackgroundCredentialStore(backend)
        val owner = operation()
        store.beginOwnerOperation(0, owner, false).value()
        backend.erase()
        store.withOwnerOperation(owner) {
            assertTrue(store.read() is CredentialStoreResult.Failure)
        }
    }

    @Test fun logoutFenceRejectsQueuedAndAlreadyRunningOwnerOperations() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val first = operation()
        store.beginOwnerOperation(0, first, false).value()
        store.fenceOwnerLogout(4).value()
        val fenced = store.read().value()
        assertTrue(store.beginOwnerOperation(fenced.revision, operation(2), false) is CredentialStoreResult.Failure)
        store.withOwnerOperation(first) { assertTrue(store.read() is CredentialStoreResult.Failure) }
        assertEquals(fenced, store.read().value())
    }

    @Test fun responseAndTransportCarryServerDeviceAndEveryIdentityField() {
        val payload = JSONObject("""{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","access_expires_in":900,"refresh_expires_in":3600,"device":{"id":"22222222-2222-4222-8222-222222222222","container_version":"0.2.16","runtime_version":"0.2.15","runtime_contract_version":1,"runtime_slot":"stable","session_generation":7}}""")
        val recovered = BackgroundSessionRecoveryResult.fromPayload(payload)
        val wire = JSONObject(recovered.responseJson)
        assertEquals("22222222-2222-4222-8222-222222222222", wire.getJSONObject("device").getString("id"))
        assertEquals("stable", wire.getJSONObject("device").getString("runtime_slot"))
        assertEquals(900, wire.getLong("access_expires_in"))
        assertFalse(recovered.toString().contains("synthetic-access"))
        val credential = BackgroundCredential(operation().scope.deviceId, "https://synthetic.invalid", "synthetic-access", 9999999999, operation().scope)
        val headers = backgroundAuthorizationHeaders(credential, BackgroundAuthorization.BEARER)
        assertEquals("Bearer synthetic-access", headers["Authorization"])
        assertEquals("0.2.15", headers["X-Nelomai-Runtime-Version"])
        assertEquals("7", headers["X-Nelomai-Session-Generation"])
        assertEquals(7, headers.size)
    }

    @Test fun scopedLegacyModeWithDisabledCapabilityKeepsBackgroundRecoveryAvailable() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val owner = operation()
        val begun = store.beginOwnerOperation(0, owner, false).value()
        val request = BackgroundUiProvisionRequest(begun.revision, owner.scope.deviceId,
            "https://synthetic.invalid", "synthetic-access", "synthetic-install", 1,
            BackgroundCapabilitySnapshot(0, false, 1), owner.scope)
        var legacyCalls = 0
        val saved = store.withOwnerOperation(owner) {
            provisionOwnedBackgroundCredential(store, request, "legacy", 100,
                provision = { error("disabled capability must not start two-phase") },
                rotate = { error("fresh install has nothing to rotate") },
                legacy = { legacyCalls++; BackgroundCredential(owner.scope.deviceId, "https://synthetic.invalid", "synthetic-background", 1000) })
        }
        assertEquals(1, legacyCalls)
        assertEquals("synthetic-background", saved.active?.token)
        assertEquals(owner.scope, saved.ownerScope)
        assertTrue(hasRecoverableBackgroundCredential(saved))
        val newer = operation(2)
        assertEquals(newer.scope, store.beginOwnerOperation(saved.revision, newer, true).value().ownerScope)
    }

    @Test fun timedOutStagedActivationSurvivesAndFreshOwnerReplaysWithoutLegacyReplacement() {
        var now = 1000L
        val store = BackgroundCredentialStore(MemoryBackend(), nowMillis = { now })
        val owner = operation().copy(expiresAtUnixMs = 2000)
        var current = store.beginOwnerOperation(0, owner, false).value()
        current = store.configure(current.revision, BackgroundCredentialProvision(owner.scope.deviceId,
            "https://synthetic.invalid", "old-background", 1000, "synthetic-install", 1,
            BackgroundCapabilitySnapshot(1, true, 1000))).value()
        current = store.reserveMutation(current.revision, "prepare", owner.scope.deviceId, 1000, 100, "activate").value()
        val pending = BackgroundPendingToken("staged-background", 1000, 2, "prepare", "activate", 1)
        current = store.savePendingToken(current.revision, "prepare", pending, 100).value()
        now = 2001
        store.withOwnerOperation(owner) {
            assertTrue(store.promotePending(current.revision, "activate", 1200) is CredentialStoreResult.Failure)
        }
        assertEquals(pending, store.read().value().pending)
        val second = operation(2).copy(expiresAtUnixMs = 3000)
        current = store.beginOwnerOperation(current.revision, second, true).value()
        val request = BackgroundUiProvisionRequest(current.revision, owner.scope.deviceId,
            "https://synthetic.invalid", "unused-access", "synthetic-install", 1,
            BackgroundCapabilitySnapshot(1, true, 1000), owner.scope)
        val replayed = store.withOwnerOperation(second) {
            provisionOwnedBackgroundCredential(store, request, "legacy", 100,
                provision = { scoped -> provisionBackgroundCredential(store, scoped, 100,
                    operationIds = { error("must replay existing operation IDs") },
                    prepare = { _, _, _, _ -> error("must not prepare another token") },
                    activate = { _, saved, _ -> assertEquals(pending, saved); BackgroundActivationResult(1200, 2) }) },
                rotate = { error("pending activation has priority") },
                legacy = { error("pending activation must not be replaced by legacy issuance") })
        }
        assertEquals("staged-background", replayed.active?.token)
        assertEquals("old-background", replayed.previous?.token)
        assertNull(replayed.pending)
    }

    @Test fun delayedRemoteOperationCannotPromoteAtOriginalDeadlineOrAfterWaiterDisappears() {
        // Same serialized owner request shape as NativeAuthRequest.operation_json.
        // Six seconds of remote control work leave four seconds at native entry.
        var now = 7000L
        val store = BackgroundCredentialStore(MemoryBackend(), nowMillis = { now })
        val wire = operation().toJson().put("expires_at_unix_ms", 11000L)
        val owner = NativeOwnerOperation.fromJson(wire)
        var current = store.beginOwnerOperation(0, owner, false).value()
        current = store.configure(current.revision, BackgroundCredentialProvision(owner.scope.deviceId,
            "https://synthetic.invalid", "old-background", 1000, "synthetic-install", 1,
            BackgroundCapabilitySnapshot(1, true, 1000))).value()
        current = store.reserveMutation(current.revision, "prepare", owner.scope.deviceId, 1000, 100, "activate").value()
        val pending = BackgroundPendingToken("staged-background", 1000, 2, "prepare", "activate", 1)
        current = store.savePendingToken(current.revision, "prepare", pending, 100).value()
        val retained = current
        for (late in listOf(11000L, 11001L, 17000L)) {
            now = late
            store.withOwnerOperation(owner) {
                val result = store.promotePending(retained.revision, "activate", 1200)
                assertEquals(CredentialStoreResult.Failure("background_owner_cancelled"), result)
            }
            assertEquals(retained, store.read().value())
            assertEquals(pending, store.read().value().pending)
            assertTrue(store.beginOwnerOperation(retained.revision, owner, true) is CredentialStoreResult.Failure)
        }
    }

    @Test fun newFamilyRequiresFinalizedCleanupAndUnknownLegacyScopeIsNeverAdmitted() {
        val store = BackgroundCredentialStore(MemoryBackend())
        val owner = operation()
        var current = store.beginOwnerOperation(0, owner, false).value()
        val provision = BackgroundCredentialProvision(owner.scope.deviceId, "https://synthetic.invalid",
            "synthetic-background", 1000, "synthetic-install", 1, BackgroundCapabilitySnapshot(0, false, 1))
        store.configure(current.revision, provision).value()
        val unknown = BackgroundCredentialStore(MemoryBackend())
        val legacy = unknown.configure(0, provision).value()
        assertTrue(unknown.beginOwnerOperation(legacy.revision, owner, true) is CredentialStoreResult.Failure)
        assertEquals(legacy, unknown.read().value())
        store.fenceOwnerLogout(4).value()
        current = store.beginLogoutCurrent("logout").value().envelope
        val newer = operation(2, 5).let { it.copy(scope = it.scope.copy(family = "new-family")) }
        assertTrue(store.beginOwnerOperation(current.revision, newer, false) is CredentialStoreResult.Failure)
        assertNotNull(store.read().value().cleanupCredential)
        current = store.finalizeLogout(current.revision, "logout").value()
        val begun = store.beginOwnerOperation(current.revision, newer, false).value()
        assertEquals(newer.scope, begun.ownerScope)
        store.withOwnerOperation(owner) { assertTrue(store.read() is CredentialStoreResult.Failure) }
    }

    private fun <T> CredentialStoreResult<T>.value(): T = (this as CredentialStoreResult.Success).value
    private class MemoryBackend : EncryptedRecordBackend {
        private var bytes: ByteArray? = null
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun write(plaintext: ByteArray): Boolean { bytes = plaintext.copyOf(); return true }
        fun erase() { bytes = null }
    }
}
