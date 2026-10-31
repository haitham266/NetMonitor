plugins {
    id("com.android.application") version "8.2.2"
    id("org.jetbrains.kotlin.android") version "1.9.22"
}
android {
    namespace = "net.netmonitor.app"
    compileSdk = 34
    defaultConfig { applicationId = "net.netmonitor.app"; minSdk = 21; targetSdk = 34; versionCode = 1; versionName = "1.0" }
    sourceSets { getByName("main") { manifest.srcFile("AndroidManifest.xml"); java.srcDirs("src") } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
