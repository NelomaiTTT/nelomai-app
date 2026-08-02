package ru.nelomai.client

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import io.crates.keyring.Keyring

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    Keyring.initializeNdkContext(applicationContext)
    super.onCreate(savedInstanceState)
  }
}
