package com.hayden.authorization.config;

import com.hayden.authorization.x509.model.X509RootCertificate;
import com.hayden.authorization.x509.repository.RootCaCertificateRepository;
import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class DataConfig {

    @Bean
    JPAQueryFactory sqlQueryFactory(EntityManager dataSource) {
        return new JPAQueryFactory(dataSource);
    }

    @Bean
    CommandLineRunner commandLineRunner(JPAQueryFactory dataSource,
                                        RootCaCertificateRepository rootCaCertificateRepository) {
        return args -> {
//            rootCaCertificateRepository.deleteAll();
//            X509RootCertificate entity = new X509RootCertificate();
//            entity.setCertificateValue(new byte[]{});
//            entity = rootCaCertificateRepository.save(entity);
//            var found = dataSource.selectFrom(QX509RootCertificate.x509RootCertificate)
//                    .select(QX509RootCertificate.x509RootCertificate)
//                    .fetch();
//            System.out.println(found);

        };
    }

}
