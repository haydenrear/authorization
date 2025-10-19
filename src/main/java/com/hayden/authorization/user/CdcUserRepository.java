package com.hayden.authorization.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CdcUserRepository extends JpaRepository<CdcUser, CdcUser.CdcUserId>, QuerydslPredicateExecutor<CdcUser>, CdcUserRepositoryCustom {
}
