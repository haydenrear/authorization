package com.hayden.authorization.config;

import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

@Component
@ConfigurationProperties(prefix = "authorization-server")
@Data
public class AuthorizationServerConfigProps {

    public record Authority(String name, AuthorityType authorityType, String mappedName) {
        public enum AuthorityType {
            COLLECTION, STRING, BOOLEAN
        }
    }

    public record ServerExtensions(String emailUri, String usernameAttribute, String emailAttribute, String nameAttribute,
                                   List<Authority> authorities) {

        public static ServerExtensions defaultServerExtensions() {
            return new ServerExtensions(null, "username", "email", "name", new ArrayList<>());
        }

        public String emailAttribute() {
            return Optional.ofNullable(emailAttribute).orElse("email");
        }

        public Optional<String> attributeFor(String name) {
            switch(name.toLowerCase()) {
                case "email":
                    return Optional.ofNullable(emailAttribute)
                            .filter(StringUtils::isNotBlank);
                case "username":
                    return Optional.ofNullable(usernameAttribute)
                            .filter(StringUtils::isNotBlank);
                case "name":
                    return Optional.ofNullable(nameAttribute)
                            .filter(StringUtils::isNotBlank);
            }

            return Optional.empty();
        }
    }

    Map<String, ServerExtensions> servers = new HashMap<>();

    Set<String> authorizedScopes = new HashSet<>();

    public URI emailUri(String server, String fallback) {
        return Optional.ofNullable(servers.get(server))
                .flatMap(se -> Optional.ofNullable(se.emailUri))
                .filter(StringUtils::isNotBlank)
                .map(URI::create)
                .orElse(URI.create(fallback));
    }

}
