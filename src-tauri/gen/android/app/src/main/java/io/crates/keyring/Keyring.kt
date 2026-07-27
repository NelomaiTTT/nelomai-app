package io.crates.keyring

import android.content.Context

class Keyring {
  companion object {
    init {
      System.loadLibrary("nelomai_app_lib")
    }

    external fun initializeNdkContext(context: Context)
  }
}
