import java.util.Properties

val release = Properties().also { properties -> rootProject.file("version.properties").inputStream().use(properties::load) }

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "io.github.cysin.sslsockspro"
    compileSdk = 37
    compileSdkMinor = 2
    buildToolsVersion = "37.0.0"
    defaultConfig {
        applicationId = "io.github.cysin.sslsockspro"
        minSdk = 36
        targetSdk = 37
        versionCode = release.getProperty("versionCode").toInt()
        versionName = release.getProperty("versionName")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        testProguardFiles("proguard-test.pro")
        ndk { abiFilters += listOf("arm64-v8a") }
    }
    ndkVersion = "30.0.16248370"
    buildFeatures { compose = true; aidl = true; buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging {
        jniLibs.useLegacyPackaging = true
        // The default services merge takes precedence over exclusions. Retain
        // only Android/JCA services so desktop DNS providers can be excluded.
        resources.merges.removeAll(setOf("META-INF/services/**", "/META-INF/services/**"))
        resources.merges += setOf("META-INF/services/java.security.Provider",
            "META-INF/services/kotlinx.coroutines.CoroutineExceptionHandler",
            "META-INF/services/kotlinx.coroutines.internal.MainDispatcherFactory")
        resources.excludes += setOf("META-INF/DEPENDENCIES", "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
            "META-INF/services/java.net.spi.InetAddressResolverProvider",
            "META-INF/services/sun.net.spi.nameservice.NameServiceDescriptor")
        resources.merges += setOf("META-INF/LICENSE.md", "META-INF/NOTICE.md")
    }
    val keyProperties = System.getenv("SSLSOCKSPRO_SIGNING_PROPERTIES")?.let { filename ->
        Properties().also { properties -> file(filename).inputStream().use(properties::load) }
    }
    signingConfigs {
        if (keyProperties != null) create("release") {
            storeFile = file(keyProperties.getProperty("storeFile"))
            storePassword = keyProperties.getProperty("storePassword")
            keyAlias = keyProperties.getProperty("keyAlias")
            keyPassword = keyProperties.getProperty("keyPassword")
        }
    }
    buildTypes {
        create("minifiedDebug") {
            initWith(getByName("debug"))
            // Exercise release optimizations with the existing test signature.
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            matchingFallbacks += listOf("debug")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (keyProperties != null) signingConfig = signingConfigs.getByName("release")
        }
    }
    testBuildType = providers.gradleProperty("testBuildType").orElse("debug").get()
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencyLocking { lockAllConfigurations() }

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("com.squareup.okhttp3:okhttp:5.5.0")
    implementation("dnsjava:dnsjava:3.6.5")
    implementation("org.apache.commons:commons-compress:1.28.0")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation(platform("androidx.compose:compose-bom:2026.09.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

// Every APK contains all engines. The builder verifies pinned inputs and
// artifact hashes, and returns quickly when its native cache is current.
val buildNative by tasks.registering(Exec::class) {
    group = "build"
    description = "Build and verify the ARM64 Android native engines"
    workingDir(rootProject.projectDir)
    commandLine("python3", rootProject.file("tools/build_native.py").absolutePath)
}
tasks.named("preBuild").configure { dependsOn(buildNative) }
