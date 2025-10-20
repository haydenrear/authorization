package com.hayden.authorization.user;


import com.hayden.persistence.models.AuditedEntity;
import com.hayden.utilitymodule.stream.StreamUtil;
import jakarta.persistence.*;
import lombok.*;
import lombok.extern.jackson.Jacksonized;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.time.Instant;
import java.util.*;

@Entity
@Builder(toBuilder = true)
@NoArgsConstructor
@Jacksonized
@AllArgsConstructor
@Table(name = "cdc_users")
@Getter
@Setter
public class CdcUser extends AuditedEntity<CdcUser.CdcUserId> implements UserDetails, OAuth2User {

    @Id
    @org.springframework.data.annotation.Id
    CdcUserId principalId;

    public boolean alreadyProcessed(String id) {
        return StreamUtil.toStream(this.credits.paymentsProcessed)
                .anyMatch(s -> Objects.equals(s, id));
    }

    @Embeddable
    public record CdcUserId (String principalId, String clientId) {}

    @Column(unique = true)
    String email;

    @Column
    String name;

    @Column
    String profile;

    @Builder.Default
    @Column(columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> authorities = new ArrayList<>();

    @Builder.Default
    @Column(columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> metadata = new HashMap<>();

    @Column
    private String authorizationCode;

    @Column(length = 4096)
    private String jwtToken;

    /**
     * TODO: email password if github for looking inside todo dashboard
     */
    @Column
    private String password;

    @Builder(toBuilder = true)
    public record Credits(int current, int history, Instant lastUpdated, List<String> paymentsProcessed) {
        public Credits(int current, int history, Instant lastUpdated) {
            this(current, history, lastUpdated, new ArrayList<>());
        }

        public static Credits empty() {
            return new Credits(0, 0, Instant.now(), new ArrayList<>());
        }
    }

    @Column(columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Credits credits;

    @Override
    public CdcUserId equalsAndHashCodeId() {
        return principalId;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return principalId.principalId;
    }

    @Override
    public String getName() {
        return this.principalId.principalId;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return metadata;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.unmodifiableList(
                authorities.stream()
                           .map(SimpleGrantedAuthority::new)
                           .toList());
    }

}
