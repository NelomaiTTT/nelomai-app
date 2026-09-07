plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

val repositoryRoot = rootDir.resolve("../../..")
fun buildValue(name: String): String = (System.getenv(name) ?: "").replace("\\", "\\\\").replace("\"", "\\\"")
val generatedStable = layout.buildDirectory.dir("generated/stableRuntime")
val prepareStableSources by tasks.registering(Exec::class) {
    dependsOn(":amneziawg-tunnel:prepareRuntimeHostAdapter")
    commandLine("python3", repositoryRoot.resolve("scripts/android/generate-stable-sources.py"),
        "--root", repositoryRoot, "--output", generatedStable.get().asFile)
}

android {
    namespace = "ru.nelomai.runtime.stable"
    resourcePrefix = "stable_runtime_"
    compileSdk = 36
    defaultConfig {
        minSdk = 24
        val version = (groovy.json.JsonSlurper().parse(repositoryRoot.resolve("src-tauri/tauri.conf.json")) as Map<*, *>)["version"] as String
        buildConfigField("String", "RUNTIME_SLOT", "\"stable\"")
        buildConfigField("String", "RUNTIME_VERSION", "\"$version\"")
        buildConfigField("String", "FIREBASE_APPLICATION_ID", "\"${buildValue("NELOMAI_FIREBASE_APPLICATION_ID")}\"")
        buildConfigField("String", "FIREBASE_API_KEY", "\"${buildValue("NELOMAI_FIREBASE_API_KEY")}\"")
        buildConfigField("String", "FIREBASE_PROJECT_ID", "\"${buildValue("NELOMAI_FIREBASE_PROJECT_ID")}\"")
        consumerProguardFiles("consumer-rules.pro")
    }
    buildFeatures { buildConfig = true }
    sourceSets.getByName("main") {
        java.srcDir(generatedStable.map { it.dir("java") })
        res.srcDir(generatedStable.map { it.dir("res") })
        manifest.srcFile(generatedStable.map { it.file("AndroidManifest.xml") })
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    kotlinOptions { jvmTarget = "17" }
}
tasks.named("preBuild").configure { dependsOn(prepareStableSources) }

dependencies {
    compileOnly(project(":runtime-android-common"))
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.0.3")
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.collection:collection:1.4.0")
    implementation("androidx.browser:browser:1.8.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.3")
    implementation("com.google.firebase:firebase-messaging:24.1.1")
    compileOnly("com.google.code.findbugs:jsr305:3.0.2")
}
