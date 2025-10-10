package com.hayden.authorization.config;

import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserDetails;
import com.hayden.authorization.user.CdcUserDetailsManager;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.jdbc.init.DataSourceScriptDatabaseInitializer;
import org.springframework.boot.sql.init.DatabaseInitializationMode;
import org.springframework.boot.sql.init.DatabaseInitializationSettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

@Slf4j
@Configuration
public class AuthenticationConfig {


    @SneakyThrows
    @Bean
    @Profile("test-auth")
    public CommandLineRunner initializeAuth(DataSource dataSource,
                                            CdcUserDetailsManager userDetailsService) {
        initializeDatabase(dataSource);
        insertUser(userDetailsService);
        return args -> {};
    }

    @SneakyThrows
    @Bean
    @Profile("!test-auth")
    public CommandLineRunner initializeDb(DataSource dataSource) {
        initializeDatabase(dataSource);
        return args -> {};
    }


    @Bean
    DaoAuthenticationProvider daoAuthenticationProvider(CdcUserDetails userDetailsService,
                                                        PasswordEncoder passwordEncoder) {
        var d = new DaoAuthenticationProvider();
        d.setUserDetailsService(userDetailsService);
        d.setPasswordEncoder(passwordEncoder);
        return d;
    }

    @Bean
    AuthenticationManager passwordAuthenticationManager(DaoAuthenticationProvider authenticationProviderList) {
        ProviderManager p = new ProviderManager(authenticationProviderList);
        return p;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    private static void insertUser(CdcUserDetailsManager mgr) {
        mgr.createUser(
                User.withUsername("user")
                        .password("password")
                        .roles("USER")
                        .build());
    }

    private static void initializeDatabase(DataSource dataSource) throws Exception {
        DatabaseInitializationSettings settings = new DatabaseInitializationSettings();
        var found = Arrays.stream(new PathMatchingResourcePatternResolver().getResources("classpath*:*schema.sql"))
                .peek(s -> {
                    log.info("Found resource {}", s);
                })
                .filter(Resource::exists)
                .map(r -> {
                    try {
                        return r.getFile();
                    } catch (IOException e) {
                        log.error("Error {}", e);
                    }
                    return null;
                })
                .filter(Objects::nonNull)
                .map(File::getAbsolutePath)
                .map(s -> "file:" + s)
                .toList();
        settings.setSchemaLocations(found);
        settings.setMode(DatabaseInitializationMode.ALWAYS);
        var i = new DataSourceScriptDatabaseInitializer(dataSource, settings) ;
        i.afterPropertiesSet();
        i.initializeDatabase();
    }
}
