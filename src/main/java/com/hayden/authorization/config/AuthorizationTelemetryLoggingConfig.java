package com.hayden.authorization.config;

import com.hayden.tracing.config.TelemetryLoggingConfig;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;

@Import(TelemetryLoggingConfig.class)
@Profile("telemetry-logging")
@Configuration
public class AuthorizationTelemetryLoggingConfig { }
