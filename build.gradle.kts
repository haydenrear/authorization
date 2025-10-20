import Com_hayden_docker_gradle.DockerContext

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
    id("com.github.node-gradle.node")
    id("com.hayden.wiremock")
}

val registryBase = project.property("registryBase") ?: "localhost:5001"

val enableDocker = project.property("enable-docker")?.toString()?.toBoolean()?.or(false) ?: false
val buildCommitDiffContext = project.property("build-authorization-server")?.toString()?.toBoolean()?.or(false) ?: false

var arrayOf = arrayOf(
    DockerContext(
        "${registryBase}/authorization-server",
        "${project.projectDir}/src/main/docker",
        "authorizationServer"
    )
)

if (!enableDocker || !buildCommitDiffContext)
    arrayOf = emptyArray<DockerContext>()

wrapDocker {
    ctx = arrayOf
}

group = "com.hayden"
version = "0.0.1-SNAPSHOT"

//tasks.register("prepareKotlinBuildScriptModel")


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
    implementation("org.modelmapper:modelmapper:3.0.0")

    // Stripe Java SDK for webhook validation
// https://mvnrepository.com/artifact/com.stripe/stripe-java
    implementation("com.stripe:stripe-java:30.0.0")
    testImplementation("com.google.code.gson:gson:2.11.0")
}

tasks.compileJava {
    dependsOn("processYmlFiles")
}

// Node.js and npm configuration
node {
    version.set("20.11.0")
    npmVersion.set("10.2.4")
    download.set(true)
    workDir.set(file("${project.layout.buildDirectory.get()}/nodejs"))
    npmWorkDir.set(file("${project.layout.buildDirectory.get()}/npm"))
}

// Build the Next.js frontend
tasks.register<com.github.gradle.node.npm.task.NpmTask>("buildFrontend") {
    description = "Build Next.js frontend application"
    workingDir.set(file("${project.projectDir}/fe"))

    args.set(listOf("run", "build"))

    inputs.files("${project.projectDir}/fe/src")
    inputs.file("${project.projectDir}/fe/package.json")
    inputs.file("${project.projectDir}/fe/next.config.ts")

    outputs.dir("${project.projectDir}/fe/.next")

    finalizedBy("copyFrontendBuild")
}

// Copy built frontend to static resources
tasks.register<Copy>("copyFrontendBuild") {

    doFirst {
        delete(file("${project.projectDir}/src/main/resources/static"))
    }

    description = "Copy Next.js build output to static resources"
    dependsOn("buildFrontend")

    from("${project.projectDir}/fe/out")
    into("${project.layout.projectDirectory}/src/main/resources/static")

}

// Make bootJar depend on frontend build
tasks.getByPath("bootJar").dependsOn("copyFrontendBuild")
