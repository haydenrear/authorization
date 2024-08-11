package com.hayden.authorization.config;

import lombok.SneakyThrows;
import org.apache.commons.compress.utils.Lists;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.jdbc.init.DataSourceScriptDatabaseInitializer;
import org.springframework.boot.sql.init.DatabaseInitializationMode;
import org.springframework.boot.sql.init.DatabaseInitializationSettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;
import java.util.List;

@Configuration
public class AuthenticationConfig {


    @SneakyThrows
    @Bean
    @Profile("test-auth")
    public CommandLineRunner initializeAuth(DataSource dataSource, UserDetailsService userDetailsService) {
        initializeDatabase(dataSource);
        insertUser(userDetailsService);
        return args -> {};
    }


    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService) {
        var d = new DaoAuthenticationProvider();
        d.setUserDetailsService(userDetailsService);
        d.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        return d;
    }

    @Bean
    AuthenticationManager passwordAuthenticationManager(DaoAuthenticationProvider authenticationProviderList) {
        ProviderManager p = new ProviderManager(authenticationProviderList);
        return p;
    }

    private static void insertUser(UserDetailsService userDetailsService) {
        if (userDetailsService instanceof JdbcUserDetailsManager mgr && !mgr.userExists("user")) {
            mgr.createUser(
                    User.withUsername("user")
                            .password("password")
                            .roles("USER")
                            .build()
            );
        }
    }

    private static void initializeDatabase(DataSource dataSource) throws Exception {
        DatabaseInitializationSettings settings = new DatabaseInitializationSettings();
        settings.setSchemaLocations(List.of("classpath:%s".formatted("schema.sql")));
        settings.setMode(DatabaseInitializationMode.ALWAYS);
        var i = new DataSourceScriptDatabaseInitializer(dataSource, settings) ;
        i.afterPropertiesSet();
        i.initializeDatabase();
    }
}
