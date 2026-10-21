buildscript {
    repositories { google(); mavenCentral() }
    dependencies { classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.21") }
    // Plugin and build classpath versions are recorded in gradle.lockfile;
    // artifact checksums are enforced by gradle/verification-metadata.xml.
    dependencyLocking { lockAllConfigurations() }
}
plugins {
    id("com.android.application") version "9.4.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.4.21" apply false
}
