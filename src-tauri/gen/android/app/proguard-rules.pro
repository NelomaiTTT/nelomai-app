# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# Runtime slot adapters are resolved by constructed class names, not direct calls.
# Their constructors and ABI methods must survive the final application R8 pass.
-keep class ru.nelomai.tunnel.LatestRuntimeVpnEngineV1 { *; }
-keep class ru.nelomai.tunnel.LatestRuntimeQuickActionsV1 { *; }
-keep class ru.nelomai.tunnel.LatestRuntimeStorageV1 { *; }
-keep class ru.nelomai.tunnel.LatestRuntimeNativeBridgeV1 { *; }

# Rust calls these methods by exact JNI names/signatures; Java references alone
# do not describe their reachability. Native entrypoint names are also ABI.
-keep class ru.nelomai.client.RuntimeNativeCallbacks { *; }
-keep class ru.nelomai.client.RuntimeNativeHost { *; }
-keep class ru.nelomai.client.RuntimeEntrypoint { *; }
-keep class ru.nelomai.runtime.v1.PersistentLogcat {
    public static java.lang.String snapshot(java.lang.String);
}
