import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scripts.tests.test_android_runtime_collisions import module


class ApkManifestTest(unittest.TestCase):
    def test_apk_version_code_must_follow_release_version(self):
        check = module('check-container-apk')
        for version, code in [('0.2.15', '2015'), ('0.2.16', '2016'), ('0.3.0', '3000'), ('1.0.0', '1000000')]:
            xml = f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionName="{version}" android:versionCode="{code}"/>'
            check.verify_version(xml, version)
            with self.assertRaises(ValueError):
                check.verify_version(xml.replace(f'Code="{code}"', 'Code="1"'), version)
            with self.assertRaises(ValueError):
                check.verify_version(xml.replace(f'Name="{version}"', 'Name="0.0.1"'), version)
        with self.assertRaises(ValueError):
            check.verify_version('<manifest/>', '0.2.16')

    def test_unrepresentable_apk_release_versions_are_rejected(self):
        check = module('check-container-apk')
        for version in ['0.0.0', '0.2.1000', '0.1000.0', '2100.0.1', '0.2.16-beta', '0.2', None]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                check.verify_version('<manifest/>', version)

    def test_acceptance_requires_stable_dex_but_shipping_still_rejects_it(self):
        check = module('check-container-apk')
        self.assertTrue(callable(getattr(check, 'verify_classes', None)), 'explicit acceptance-only DEX gate is missing')
        latest = {'ru.nelomai.client.MainActivity', 'ru.nelomai.client.RuntimeAuthBrokerService',
            'ru.nelomai.client.RuntimeVpnDispatcherService', 'ru.nelomai.client.LatestRuntimeActivity',
            'ru.nelomai.tunnel.LatestRuntimeVpnEngineV1',
            'ru.nelomai.tunnel.LatestRuntimeQuickActionsV1', 'ru.nelomai.tunnel.LatestRuntimeStorageV1',
            'ru.nelomai.tunnel.LatestRuntimeNativeBridgeV1', 'ru.nelomai.client.RuntimeNativeCallbacks',
            'ru.nelomai.client.RuntimeNativeHost', 'ru.nelomai.client.RuntimeEntrypoint'}
        stable = {'ru.nelomai.runtime.stable.LatestRuntimeActivity', 'ru.nelomai.runtime.stable.RuntimeEntrypoint',
            'ru.nelomai.runtime.stable.tunnel.LatestRuntimeVpnEngineV1',
            'ru.nelomai.runtime.stable.tunnel.LatestRuntimeQuickActionsV1',
            'ru.nelomai.runtime.stable.tunnel.LatestRuntimeStorageV1',
            'ru.nelomai.runtime.stable.tunnel.LatestRuntimeNativeBridgeV1'}
        check.verify_classes(latest)
        check.verify_classes(latest | stable, acceptance=True)
        for name in latest:
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, name):
                check.verify_classes(latest - {name})
        for name in stable:
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, name):
                check.verify_classes((latest | stable) - {name}, acceptance=True)
        with self.assertRaisesRegex(ValueError, 'latest-only'):
            check.verify_classes(latest | stable)
        with self.assertRaisesRegex(ValueError, 'stable'):
            check.verify_classes(latest, acceptance=True)

    def test_acceptance_slot_gate_requires_both_exact_approved_digests(self):
        check = module('check-container-apk')
        self.assertTrue(callable(getattr(check, 'verify_slots', None)), 'root-bound acceptance slot gate is missing')
        value = {'slots': [{'slot':'latest', 'manifest':{'runtime_version':'0.2.17'}},
                           {'slot':'stable', 'manifest':{'runtime_version':'0.2.16'}}],
                 'stable_release_set_sha256':'a'*64, 'stable_platform_manifest_sha256':'b'*64}
        check.verify_slots(value, acceptance=True, root_digest='a'*64, stable_digest='b'*64)
        for root, stable in [('c'*64, 'b'*64), ('a'*64, 'c'*64), (None, None)]:
            with self.assertRaises(ValueError):
                check.verify_slots(value, acceptance=True, root_digest=root, stable_digest=stable)
        with self.assertRaisesRegex(ValueError, 'latest'):
            check.verify_slots(value)

    def test_tampered_container_signature_is_not_packaging_success(self):
        check = module('check-container-apk')
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        value = b'{"format_version":1}'
        signature = key.sign(b'nelomai-container-manifest-v1\0' + value)
        check.verify_signature(value, signature, public)
        with self.assertRaisesRegex(ValueError, 'signature'):
            check.verify_signature(value, bytes(64), public)

    def test_second_vpn_or_exported_broker_is_rejected(self):
        check = module('check-container-apk')
        prefix = '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="ru.nelomai.client"><application>'
        vpn = '<service android:name="ru.nelomai.client.RuntimeVpnDispatcherService" android:exported="false" android:permission="android.permission.BIND_VPN_SERVICE" android:process=":vpn"/>'
        broker = '<service android:name="ru.nelomai.client.RuntimeAuthBrokerService" android:exported="false"/>'
        launcher = '<activity android:name="ru.nelomai.client.MainActivity" android:exported="true"/>'
        runtime = '<activity android:name="ru.nelomai.client.LatestRuntimeActivity" android:exported="false" android:process=":runtime"/>'
        lifecycle = '<provider android:name="androidx.startup.InitializationProvider" android:exported="false" android:process=":runtime"><meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup"/></provider>'
        xml = prefix + vpn + broker + launcher + runtime + lifecycle + '</application></manifest>'
        check.verify_manifest(xml)
        for broken in ['', lifecycle.replace('android:process=":runtime"', ''),
                       lifecycle.replace('ProcessLifecycleInitializer', 'UnknownInitializer')]:
            with self.subTest(lifecycle=broken), self.assertRaisesRegex(ValueError, 'lifecycle'):
                check.verify_manifest(xml.replace(lifecycle, broken))
        with self.assertRaisesRegex(ValueError, 'VPN'):
            check.verify_manifest(xml.replace('</application>', vpn.replace('RuntimeVpnDispatcherService', 'LegacyVpn') + '</application>'))
        with self.assertRaisesRegex(ValueError, 'broker'):
            check.verify_manifest(xml.replace(broker, broker.replace('false', 'true')))


if __name__ == '__main__':
    unittest.main()
