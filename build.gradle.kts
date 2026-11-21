// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.externalproperties) apply false
}

allprojects {
    // The vendored JFileServer sources predate many API deprecations, don't drown the app's own warnings in them
    if (name != "jfileserver") {
        tasks.withType<JavaCompile>().configureEach {
            options.compilerArgs.add("-Xlint:deprecation")
        }
    }
}