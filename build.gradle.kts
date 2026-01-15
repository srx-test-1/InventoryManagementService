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
    implementation ("commons-fileupload:commons-fileupload:1.6.0")
    implementation ("org.apache.commons:commons-lang3:3.12.0")
    implementation ("org.apache.commons:commons-collections4:4.5.0-M1")

    implementation ("org.springframework.boot:spring-boot-starter-web:2.6.6") // Updated for CVE-2022-22965 (Spring4Shell)

    // Upgrade to Log4j2 which resolves vulnerabilities found in Log4j 1.x and Log4Shell (CVE-2021-44228)
    implementation ("org.apache.logging.log4j:log4j-core:2.17.1")
    implementation ("org.apache.logging.log4j:log4j-api:2.17.1")

    // Upgrade to latest Gson version
    implementation ("com.google.code.gson:gson:2.10.1")


    implementation ("com.google.guava:guava:31.1-jre")

    implementation ("com.fasterxml.jackson.core:jackson-databind:2.15.0")

    implementation ("com.fasterxml.jackson.core:jackson-core:2.15.0")

    implementation ("com.fasterxml.jackson.core:jackson-annotations:2.15.0")

    implementation ("commons-net:commons-net:3.9.0")


    testImplementation ("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.8.1")

}

tasks.test {
    useJUnitPlatform()
}