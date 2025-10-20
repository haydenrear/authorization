package com.hayden.authorization.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RestConfig {

    @Bean
    public RestTemplateBuilder authorizationRestTemplateBuilder() {
        return new RestTemplateBuilder();
    }

}
