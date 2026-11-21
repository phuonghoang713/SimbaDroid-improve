/*
 * JFileServer, vendored into SimbaDroid and extended with SMB2/SMB3 support.
 *
 * Based on https://github.com/buttercookie42/jfileserver (a fork of https://github.com/FileSysOrg/jfileserver),
 * licensed under the LGPL-3.0, see LICENSE in this directory.
 */
plugins {
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    // The upstream sources use many APIs that have since been deprecated
    options.compilerArgs.addAll(listOf("-Xlint:-removal", "-Xlint:-deprecation"))
}

dependencies {
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.jna)
    implementation(libs.jna.platform)
    implementation(libs.gson)

    testImplementation(libs.junit)

    // Independent SMB client implementations, used to test interoperability of the server. They use the same
    // Bouncy Castle version as the server.
    testImplementation(libs.smbj) {
        exclude(group = "org.bouncycastle")
    }
    testImplementation(libs.jcifs.ng) {
        exclude(group = "org.bouncycastle")
    }
    testRuntimeOnly(libs.slf4j.provider)
}

tasks.test {
    useJUnit()
    maxHeapSize = "1g"

    testLogging {
        events("failed", "skipped")
        showStandardStreams = false
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
