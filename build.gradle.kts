plugins {
    id("com.android.application") version "8.5.2"
    id("org.jetbrains.kotlin.android") version "2.0.21"
}

android {
    namespace = "net.netmonitor.app"
    compileSdk = 34

    defaultConfig {
        // معرّف مختلف عن نسخة الهيثم حتى يُثبّت التطبيقان بجانب بعض
        applicationId = "net.netmonitor.app"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    sourceSets["main"].apply {
        manifest.srcFile("AndroidManifest.xml")
        java.srcDirs("src")
    }

    buildTypes {
        getByName("release") { isMinifyEnabled = false }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
