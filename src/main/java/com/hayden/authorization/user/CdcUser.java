package com.hayden.authorization.user;


import com.hayden.persistence.models.AuditedEntity;
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

    @Embeddable
    public record CdcUserId (String principalId, String clientId) {}

    @Column(unique = true)
    String email;

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

    @Column(length = 2048)
    private String jwtToken;

    /**
     * TODO: email password if github for looking inside todo dashboard
     */
    @Column
    private String password;

    @Builder
    public record Credits(int current, int history, Instant lastUpdated) {}

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
