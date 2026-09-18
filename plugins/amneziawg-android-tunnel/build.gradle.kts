plugins {
    id("com.android.library")
}

val repositoryRoot = rootDir.resolve("../../../vendor/amneziawg-android")
val goBackendRoot = rootDir.resolve("../../../vendor/amneziawg-go")
val tunnelRoot = repositoryRoot.resolve("tunnel")
val generatedLicenseAssets = layout.buildDirectory.dir("generated/amneziawgLicenseAssets")
val repositoryProjectRoot = rootDir.resolve("../../..")
val generatedHostJava = layout.buildDirectory.dir("generated/runtimeHostJava")
val prepareRuntimeHostAdapter by tasks.registering(Exec::class) {
    commandLine("python3", repositoryProjectRoot.resolve("scripts/android/generate-vpn-host-adapter.py"),
        "--root", repositoryProjectRoot, "--output", generatedHostJava.get().asFile)
    inputs.files(repositoryProjectRoot.resolve("scripts/android/generate-vpn-host-adapter.py"),
        repositoryProjectRoot.resolve("patches/amneziawg-android-network-telemetry.patch"),
        repositoryProjectRoot.resolve("patches/amneziawg-android-memory-diagnostics.patch"),
        repositoryProjectRoot.resolve("patches/amneziawg-android-service-lifecycle.patch"))
    outputs.dir(generatedHostJava)
}
val applyAmneziaWgOverrides by tasks.registering(Exec::class) {
    workingDir(repositoryProjectRoot)
    commandLine("bash", "scripts/android/apply-amneziawg-overrides.sh")
}
val prepareAmneziaWgLicense by tasks.registering(Copy::class) {
    from(repositoryRoot.resolve("COPYING")) {
        rename { "AMNEZIAWG-ANDROID-APACHE-2.0.txt" }
    }
    from(tunnelRoot.resolve("tools/amneziawg-tools/COPYING")) {
        rename { "AMNEZIAWG-TOOLS-GPL-2.0.txt" }
    }
    from(tunnelRoot.resolve("tools/elf-cleaner/COPYING")) {
        rename { "ELF-CLEANER-GPL-2.0.txt" }
    }
    from(goBackendRoot.resolve("LICENSE")) {
        rename { "AMNEZIAWG-GO-MIT.txt" }
    }
    from(projectDir.resolve("SOURCE-OFFER.txt"))
    into(generatedLicenseAssets.map { it.dir("licenses") })
}

android {
    namespace = "org.amnezia.awg.tunnel"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = 24
        ndk {
            abiFilters += "arm64-v8a"
        }
        if (!project.hasProperty("nelomaiRuntimeInputs")) externalNativeBuild {
            cmake {
                targets("libwg-go.so", "libwg.so", "libwg-quick.so")
                arguments(
                    "-DANDROID_PACKAGE_NAME=ru.nelomai.client",
                    "-DGRADLE_USER_HOME=${project.gradle.gradleUserHomeDir}",
                )
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            manifest.srcFile(projectDir.resolve("AndroidManifest.xml"))
            java.srcDir(generatedHostJava)
            assets.srcDir(generatedLicenseAssets)
        }
    }

    if (!project.hasProperty("nelomaiRuntimeInputs")) externalNativeBuild {
        cmake {
            path = tunnelRoot.resolve("tools/CMakeLists.txt")
        }
    }

    lint {
        disable += "LongLogTag"
        disable += "NewApi"
    }
}

tasks.named("preBuild").configure {
    dependsOn(prepareRuntimeHostAdapter)
    dependsOn(applyAmneziaWgOverrides)
    dependsOn(prepareAmneziaWgLicense)
}

tasks.matching { it.name.startsWith("configureCMake") }.configureEach {
    dependsOn(applyAmneziaWgOverrides)
}

dependencies {
    implementation(project(":runtime-android-common"))
    implementation("androidx.annotation:annotation:1.7.1")
    implementation("androidx.collection:collection:1.4.0")
    compileOnly("com.google.code.findbugs:jsr305:3.0.2")
}
