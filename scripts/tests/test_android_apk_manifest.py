import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scripts.tests.test_android_runtime_collisions import module


class ApkManifestTest(unittest.TestCase):
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
        xml = prefix + vpn + broker + launcher + runtime + '</application></manifest>'
        check.verify_manifest(xml)
        with self.assertRaisesRegex(ValueError, 'VPN'):
            check.verify_manifest(xml.replace('</application>', vpn.replace('RuntimeVpnDispatcherService', 'LegacyVpn') + '</application>'))
        with self.assertRaisesRegex(ValueError, 'broker'):
            check.verify_manifest(xml.replace(broker, broker.replace('false', 'true')))


if __name__ == '__main__':
    unittest.main()
