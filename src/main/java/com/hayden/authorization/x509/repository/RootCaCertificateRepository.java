package com.hayden.authorization.x509.repository;

import com.hayden.authorization.x509.model.X509CertificateId;
import com.hayden.authorization.x509.model.X509RootCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RootCaCertificateRepository extends JpaRepository<X509RootCertificate, Long>,
        QuerydslPredicateExecutor<X509RootCertificate> {

    Optional<X509RootCertificate> findX509RootCertificateByUniqueId(X509CertificateId uniqueId);

}
