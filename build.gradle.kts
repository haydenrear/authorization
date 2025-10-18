import Com_hayden_docker_gradle.DockerContext
import java.nio.file.Paths

plugins {
    id("com.hayden.graphql-data-service")
    id("com.hayden.spring-app")
    id("com.hayden.observable-app")
    id("com.hayden.jpa-persistence")
    id("com.hayden.crypto")
    id("com.hayden.docker-compose")
    id("com.hayden.web-app")
    id("com.hayden.security")
    id("com.hayden.paths")
    id("com.hayden.docker")
}

val registryBase = project.property("registryBase") ?: "localhost:5001"


wrapDocker {
    ctx = arrayOf(
        DockerContext(
            "${registryBase}/authorization-server",
            "${project.projectDir}/src/main/docker",
            "authorizationServer"
        )
    )
}

group = "com.hayden"
version = "0.0.1-SNAPSHOT"

tasks.register("prepareKotlinBuildScriptModel")

val enableDocker = project.property("enable-docker")?.toString()?.toBoolean()?.or(false) ?: false
val buildCommitDiffContext = project.property("build-authorization-server")?.toString()?.toBoolean()?.or(false) ?: false

if (enableDocker && buildCommitDiffContext) {
    tasks.getByPath("bootJar").finalizedBy("buildDocker")

    tasks.getByPath("bootJar").doLast {
        tasks.getByPath("authorizationServerDockerImage")
            .dependsOn(project(":runner_code").tasks.getByName("runnerTask"), "copyJar")
    }

    tasks.register("buildDocker") {
        dependsOn("copyJar", "authorizationServerDockerImage")
        doLast {
            delete(fileTree(file(layout.projectDirectory).resolve("src/main/docker")) {
                include("**/*.jar")
            })
        }
    }
}


tasks.bootJar {
    archiveFileName = "authorization-server.jar"
    enabled = true
}

dependencies {
    implementation(project(":tracing"))

    implementation(project(":utilitymodule"))
    implementation(project(":jpa-persistence"))
    implementation(project(":commit-diff-model"))
    implementation(project(":runner_code"))
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")

    implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")

}

tasks.compileJava {
    dependsOn("processYmlFiles")
}
