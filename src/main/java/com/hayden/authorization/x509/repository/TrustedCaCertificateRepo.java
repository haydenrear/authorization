package com.hayden.authorization.x509.repository;

import com.hayden.authorization.x509.model.TrustedUserX509Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TrustedCaCertificateRepo extends JpaRepository<TrustedUserX509Certificate, Long>,
        QuerydslPredicateExecutor<TrustedUserX509Certificate> {
}
