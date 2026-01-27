import org.gradle.wrapper.Download

plugins {
    id("java")
    id("de.undercouch.download") version "5.3.0"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

tasks.register("downloadNewrelic") {
    doLast {
            val newrelicDir = file("newrelic")
            if (!newrelicDir.exists()) {
                newrelicDir.mkdirs() // Create the directory if it doesn't exist
            }
        ant.invokeMethod("get", mapOf(
            "src" to "https://download.newrelic.com/newrelic/java-agent/newrelic-agent/current/newrelic-java.zip",
            "dest" to file("newrelic/newrelic-java.zip")
        ))
    }
}

tasks.register<Copy>("unzipNewrelic") {
    from(zipTree(file("newrelic/newrelic-java.zip")))
    into(rootDir)
}

dependencies {
    // Import Spring Boot BOM for dependency management
    implementation(platform("org.springframework.boot:spring-boot-dependencies:2.7.18"))
    
    // Import Spring Framework BOM to override version to 5.3.34 (patches CVE-2024-22262)
    implementation(platform("org.springframework:spring-framework-bom:5.3.34"))
    
    implementation ("commons-fileupload:commons-fileupload:1.3.3")
    implementation ("org.apache.commons:commons-lang3:3.9")
    implementation ("org.apache.commons:commons-collections4:4.4")

    // Upgraded from 2.5.10 to 2.7.18 to get latest stable Spring Boot 2.x release
    implementation ("org.springframework.boot:spring-boot-starter-web:2.7.18")

    // Add Log4j2 core for application code that uses Log4j APIs (version managed by Spring Boot 2.7.18: 2.17.2)
    implementation ("org.apache.logging.log4j:log4j-core")
    implementation ("org.apache.logging.log4j:log4j-api")

    // Upgrade to latest Gson version
    implementation ("com.google.code.gson:gson:2.8.9")


    implementation ("com.google.guava:guava:18.0")

    implementation ("com.fasterxml.jackson.core:jackson-databind:2.8.11")

    implementation ("com.fasterxml.jackson.core:jackson-core:2.8.11")

    implementation ("com.fasterxml.jackson.core:jackson-annotations:2.8.11")

    implementation ("commons-net:commons-net:3.6")


    testImplementation ("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.8.1")

}

tasks.test {
    useJUnitPlatform()
}