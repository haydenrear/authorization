package com.hayden.authorization;

import com.hayden.persistence.config.HibernateConfig;
import com.hayden.persistence.config.JpaConfig;
import com.hayden.persistence.config.QueryDslConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({HibernateConfig.class, JpaConfig.class, QueryDslConfig.class})
public class AuthorizationApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApplication.class, args);
    }

}
