import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}
val runtimeInputs = providers.gradleProperty("nelomaiRuntimeInputs").orNull?.let { file(it) }
val acceptancePackage = providers.gradleProperty("nelomaiAcceptance").orNull == "true"
val stableRuntimeAar = providers.gradleProperty("nelomaiStableRuntimeAar").orNull?.let { file(it) }
check(acceptancePackage || stableRuntimeAar == null) { "Stable AAR linking is restricted to the separate acceptance package" }
if (acceptancePackage) {
    check(stableRuntimeAar?.isFile == true) { "Acceptance packaging requires the exact final stable runtime AAR" }
}
val verifyRuntimeBuildInputs by tasks.registering {
    doLast {
        val inputs = requireNotNull(runtimeInputs) { "Stage signed runtime APK inputs and pass -PnelomaiRuntimeInputs=<apk inputs directory>" }
        for (name in listOf("assets/runtime/container-manifest-v1.json", "assets/runtime/container-manifest-v1.sig",
            "jniLibs/arm64-v8a/libnelomai_android_container.so", "jniLibs/arm64-v8a/libnelomai_app_lib.so", "jniLibs/arm64-v8a/libwg-go.so")) {
            check(inputs.resolve(name).isFile) { "Missing compiled runtime input: $name" }
        }
        if (acceptancePackage) {
            for (name in listOf("libnelomai_runtime_stable.so", "libstable_runtime_wg_go.so")) {
                check(inputs.resolve("jniLibs/arm64-v8a/$name").isFile) { "Missing exact stable native input: $name" }
            }
        }
    }
}
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }.configureEach { dependsOn(verifyRuntimeBuildInputs) }
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        FileInputStream(keystorePropertiesFile).use { load(it) }
    }
}
val releaseKeyAlias = System.getenv("ANDROID_KEY_ALIAS")
    ?: keystoreProperties.getProperty("keyAlias")
val releaseStorePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
    ?: keystoreProperties.getProperty("storePassword")
    ?: keystoreProperties.getProperty("password")
val releaseKeyPassword = System.getenv("ANDROID_KEY_PASSWORD")
    ?: keystoreProperties.getProperty("keyPassword")
    ?: keystoreProperties.getProperty("password")
val releaseStoreFile = System.getenv("ANDROID_KEYSTORE_PATH")
    ?: keystoreProperties.getProperty("storeFile")
val releaseSigningConfigured = listOf(
    releaseKeyAlias,
    releaseStorePassword,
    releaseKeyPassword,
    releaseStoreFile,
).all { !it.isNullOrBlank() }

android {
    compileSdk = 36
    namespace = "ru.nelomai.client"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "ru.nelomai.client"
        minSdk = 24
        targetSdk = 36
        val sourceVersion = (groovy.json.JsonSlurper().parse(rootDir.resolve("../../../src-tauri/tauri.conf.json")) as Map<*, *>)["version"] as String
        check(sourceVersion.matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+"))) { "Android release version must be major.minor.patch" }
        val (major, minor, patch) = sourceVersion.split('.').map { it.toLong() }
        check(major <= 2100 && minor <= 999 && patch <= 999) { "Android release version exceeds versionCode range" }
        val sourceCode = major * 1_000_000 + minor * 1_000 + patch
        check(sourceCode in 1..2_100_000_000L) { "Android versionCode is out of range" }
        check(tauriProperties.getProperty("tauri.android.versionCode", sourceCode.toString()).toLong() == sourceCode &&
            tauriProperties.getProperty("tauri.android.versionName", sourceVersion) == sourceVersion) {
            "Stale tauri.properties: Android version must match tauri.conf.json"
        }
        versionCode = sourceCode.toInt()
        versionName = sourceVersion
        buildConfigField("String", "RUNTIME_SLOT", "\"latest\"")
        val runtimeVersion = if (acceptancePackage) "0.2.18" else sourceVersion
        buildConfigField("String", "RUNTIME_VERSION", "\"$runtimeVersion\"")
    }
    signingConfigs {
        if (releaseSigningConfigured) {
            create("release") {
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
                storeFile = file(releaseStoreFile!!)
                storePassword = releaseStorePassword
            }
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            if (releaseSigningConfigured) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    buildFeatures {
        buildConfig = true
    }
    testOptions.unitTests.isIncludeAndroidResources = true
    // The host checks the exact read-only installed ELF bytes before allowing
    // System.loadLibrary; keep a concrete nativeLibraryDir on every API level.
    packaging.jniLibs.useLegacyPackaging = true
    // Svelte's signed WebView payload contains _app; AAPT's default <dir>_*
    // exclusion would silently remove indexed files and block host admission.
    androidResources.ignoreAssetsPattern = "!.svn:!.git:!.ds_store:!*.scc:.*:!CVS:!thumbs.db:!picasa.ini:!*~"
    runtimeInputs?.let { inputs -> sourceSets.getByName("main") {
        assets.srcDir(inputs.resolve("assets"))
        jniLibs.srcDir(inputs.resolve("jniLibs"))
    } }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    if (acceptancePackage) {
        // Link final candidate classes/resources; never rebuild the stable AAR.
        implementation(files(stableRuntimeAar!!))
    }
    implementation(project(":runtime-android-common"))
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.0.3")
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = "tauri.build.gradle.kts")
