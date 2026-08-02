package ru.nelomai.client

import android.os.Bundle
import io.crates.keyring.Keyring

class QuickActionActivity : TauriActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(R.style.Theme_nelomai_quick_action)
        Keyring.initializeNdkContext(applicationContext)
        super.onCreate(savedInstanceState)
    }
}
