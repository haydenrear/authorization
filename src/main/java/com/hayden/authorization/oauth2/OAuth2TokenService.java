package com.hayden.authorization.oauth2;

import jakarta.annotation.Nullable;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.intellij.lang.annotations.Language;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class OAuth2TokenService {

    private final OAuth2AuthorizationService authzService;

    private final EntityManager jdbc;

    public List<OAuth2Authorization> findByPrincipal(String principal, @Nullable String clientId, int limit, int offset) {
        @Language("sql") var sql = """
            select id from oauth2_authorization
            where principal_name = ?
              and (? is null or registered_client_id = ?)
            order by id
            limit ? offset ?
        """;
        List<String> ids = jdbc.createNativeQuery(sql, String.class)
                .setParameter(1, principal)
                .setParameter(2, clientId)
                .setParameter(3, clientId)
                .setParameter(4, limit)
                .setParameter(5, offset)
                .getResultList();

        return ids.stream()
                .map(authzService::findById)
                .filter(Objects::nonNull)
                .toList();
    }
}
