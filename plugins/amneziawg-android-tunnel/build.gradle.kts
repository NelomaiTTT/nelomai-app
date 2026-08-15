plugins {
    id("com.android.library")
}

val repositoryRoot = rootDir.resolve("../../../vendor/amneziawg-android")
val goBackendRoot = rootDir.resolve("../../../vendor/amneziawg-go")
val tunnelRoot = repositoryRoot.resolve("tunnel")
val generatedLicenseAssets = layout.buildDirectory.dir("generated/amneziawgLicenseAssets")
val repositoryProjectRoot = rootDir.resolve("../../..")
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
        externalNativeBuild {
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
            manifest.srcFile(tunnelRoot.resolve("src/main/AndroidManifest.xml"))
            java.srcDir(tunnelRoot.resolve("src/main/java"))
            assets.srcDir(generatedLicenseAssets)
        }
    }

    externalNativeBuild {
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
    dependsOn(applyAmneziaWgOverrides)
    dependsOn(prepareAmneziaWgLicense)
}

tasks.matching { it.name.startsWith("configureCMake") }.configureEach {
    dependsOn(applyAmneziaWgOverrides)
}

dependencies {
    implementation("androidx.annotation:annotation:1.7.1")
    implementation("androidx.collection:collection:1.4.0")
    compileOnly("com.google.code.findbugs:jsr305:3.0.2")
}
