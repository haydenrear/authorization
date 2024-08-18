plugins {
    id("com.hayden.spring-app")
    id("com.hayden.jpa-persistence")
    id("com.hayden.crypto")
    id("com.hayden.docker-compose")
    id("com.hayden.web-app")
    id("com.hayden.security")
}

group = "com.hayden"
version = "0.0.1-SNAPSHOT"

tasks.register("prepareKotlinBuildScriptModel")

dependencies {

    implementation(project(":utilitymodule"))
    implementation(project(":jpa-persistence"))

    implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
    implementation("com.webauthn4j:webauthn4j-spring-security-core:0.10.0.RELEASE")

}
