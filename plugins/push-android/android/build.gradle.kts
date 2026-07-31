plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

fun buildValue(name: String): String =
    (System.getenv(name) ?: "").replace("\\", "\\\\").replace("\"", "\\\"")

android {
    namespace = "ru.nelomai.push"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        buildConfigField("String", "FIREBASE_APPLICATION_ID", "\"${buildValue("NELOMAI_FIREBASE_APPLICATION_ID")}\"")
        buildConfigField("String", "FIREBASE_API_KEY", "\"${buildValue("NELOMAI_FIREBASE_API_KEY")}\"")
        buildConfigField("String", "FIREBASE_PROJECT_ID", "\"${buildValue("NELOMAI_FIREBASE_PROJECT_ID")}\"")
    }

    buildFeatures {
        buildConfig = true
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core:1.16.0")
    implementation("com.google.firebase:firebase-messaging:24.1.1")
    implementation(project(":tauri-android"))
}
