package com.hayden.authorization.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;
import org.springframework.data.repository.query.FluentQuery;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CdcUserRepository extends JpaRepository<CdcUser, CdcUser.CdcUserId>, QuerydslPredicateExecutor<CdcUser>, CdcUserRepositoryCustom {

    Logger log = LoggerFactory.getLogger(CdcUserRepository.class);

    default Optional<CdcUser> findForToken(Jwt jwt) {
        List<CdcUser> multiple = this.findBy(QCdcUser.cdcUser.principalId.principalId.eq(jwt.getSubject()), FluentQuery.FetchableFluentQuery::all);

        if (multiple.size() > 1) {
            log.error("Found principal with multiple associated id: {}", jwt.getSubject());
        }

        return multiple.stream().findFirst();
    }

}
