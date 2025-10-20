package com.hayden.authorization.oauth2;

import com.hayden.authorization.config.AuthorizationServerConfigProps;
import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserRepository;
import com.hayden.utilitymodule.MapFunctions;
import com.hayden.utilitymodule.stream.StreamUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
@Slf4j
public class SocialRegistrationOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final CdcUserRepository cdcUserRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthorizationServerConfigProps configProps;

    private final RestTemplateBuilder authorizationRestTemplateBuilder;


    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest req) throws OAuth2AuthenticationException {
        OAuth2User remote = delegate.loadUser(req);
        Optional<String> email = tryGetEmail(req, remote);
        String id = tryGetUsername(req, remote).orElse(remote.getName());
        String name = tryGetName(req, remote).orElse(remote.getName());
        String accessToken = req.getAccessToken().getTokenValue();
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId(id, "cdc");
        Set<String> authorities = tryGetAuthorities(req, remote);

        var attrs = MapFunctions.CollectMap(
                remote.getAttributes().entrySet()
                        .stream()
                        .filter(e -> e.getKey() != null && e.getValue() != null)
                        .map(e -> Map.entry(
                                "%s_%s".formatted(namePrefix(req), e.getKey()),
                                e.getValue())));


        var createUpdate = cdcUserRepository.findById(userId)
                .map(user -> {
                    user.setAuthorizationCode(accessToken);
                    if (user.getEmail() == null)
                        email.ifPresent(user::setEmail);
                    if (user.getName() == null)
                        user.setName(name);

                    var edited = MapFunctions.CollectMap(user.getAttributes().entrySet().stream()
                                    .filter(e ->
                                            !e.getKey().startsWith(namePrefix(req)) ||
                                            attrs.containsKey(e.getKey())));

                    user.setMetadata(edited);

                    var editedAuthorities = user.getAuthorities().stream()
                            .filter(e ->
                                    !e.getAuthority().startsWith(namePrefix(req)) ||
                                            authorities.contains(e.getAuthority()))
                            .map(GrantedAuthority::getAuthority)
                            .toList();

                    user.setAuthorities(editedAuthorities);
                    return cdcUserRepository.save(user);
                })
                .orElseGet(() -> {
                    return cdcUserRepository.save(
                            CdcUser.builder()
                                    .authorities(new ArrayList<>())
                                    .metadata(attrs)
                                    .principalId(userId)
                                    .name(name)
                                    .credits(CdcUser.Credits.empty())
                                    .email(email.orElse(null))
                                    .password(passwordEncoder.encode(accessToken))
                                    .authorizationCode(accessToken)
                                    .authorities(new ArrayList<>(authorities))
                                    .build());
                });


        return createUpdate;
    }

    private static @NotNull String namePrefix(OAuth2UserRequest req) {
        return req.getClientRegistration().getRegistrationId().toUpperCase();
    }

    private Optional<String> tryGetUsername(OAuth2UserRequest req, OAuth2User remote) {
        return tryGetAttr(req, remote, "username");
    }

    private Optional<String> tryGetName(OAuth2UserRequest req, OAuth2User remote) {
        return tryGetAttr(req, remote, "name");
    }

    private Optional<String> tryGetEmail(OAuth2UserRequest req, OAuth2User remote) {
        return tryGetAttr(req, remote, "email")
                .or(() -> {
                    if ("github".equals(req.getClientRegistration().getRegistrationId())) {
                        try {
                            return getEmailGithubRest(req, serverExtensionOrDefault(req));
                        } catch (
                                Exception e) {
                            log.error("Error when requesting user email", e);
                        }
                    }

                    return Optional.empty();
                });
    }

    private @NotNull Set<String> tryGetAuthorities(OAuth2UserRequest req, OAuth2User remote) {
        return serverExtension(req)
                .stream()
                .flatMap(se -> se.authorities().stream())
                .flatMap(attr -> {
                    try {
                        return Stream.ofNullable(remote.getAttribute(attr.name()))
                                .flatMap(obj -> switch (attr.authorityType()) {
                                    case COLLECTION -> {
                                        if (obj instanceof Collection<?> c) {
                                            yield StreamUtil.toStream(c)
                                                    .filter(Objects::nonNull)
                                                    .map(Objects::toString);
                                        }

                                        yield Stream.empty();
                                    }
                                    case STRING ->
                                            StreamUtil.toStream(Objects.toString(obj));
                                    case BOOLEAN -> {
                                        if (obj instanceof Boolean b) {
                                            if (b)
                                                yield StreamUtil.toStream(Objects.toString(obj));
                                            yield Stream.empty();
                                        } else {
                                            try {
                                                if (Boolean.parseBoolean(Objects.toString(obj))) {
                                                    yield StreamUtil.toStream(Objects.toString(obj));
                                                }
                                                yield Stream.empty();
                                            } catch (
                                                    Exception e) {
                                                log.error("Error when requesting user email", e);
                                                yield Stream.empty();
                                            }
                                        }
                                    }
                                });
                    } catch (Exception e) {
                        log.error("Error when reading attr {}", attr, e);
                        return Stream.empty();
                    }
                })
                .filter(StringUtils::isNotBlank)
                .map(s -> "%s_%s".formatted(namePrefix(req), s))
                .collect(Collectors.toSet());
    }

    private @NotNull Optional<String> tryGetAttr(OAuth2UserRequest req, OAuth2User remote, String attributeToGet) {
        return serverExtension(req)
                .flatMap(se -> se.attributeFor(attributeToGet))
                .flatMap(attr -> Optional.ofNullable(remote.getAttribute(attr)))
                .map(Objects::toString)
                .filter(StringUtils::isNotBlank);
    }

    private @NotNull AuthorizationServerConfigProps.ServerExtensions serverExtensionOrDefault(OAuth2UserRequest req) {
        return serverExtension(req) .orElse(AuthorizationServerConfigProps.ServerExtensions.defaultServerExtensions());
    }

    private @NotNull Optional<AuthorizationServerConfigProps.ServerExtensions> serverExtension(OAuth2UserRequest req) {
        return Optional.ofNullable(this.configProps.getServers().get(req.getClientRegistration().getRegistrationId()));
    }

    private @NotNull Optional<String> getEmailGithubRest(OAuth2UserRequest req,
                                                         AuthorizationServerConfigProps.ServerExtensions serverAttributes) {
        String token = req.getAccessToken().getTokenValue();

        // Call /user/emails to get private emails
        RequestEntity<Void> request = RequestEntity
                .get(this.configProps.emailUri("github", "https://api.github.com/user/emails"))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();

        ResponseEntity<List<Map<String, Object>>> resp = authorizationRestTemplateBuilder.build()
                .exchange(request, new ParameterizedTypeReference<>() {
                });

        String email = StreamUtil.toStream(resp.getBody())
                .filter(m -> Boolean.TRUE.equals(m.get("verified")))
                .sorted((a, b) -> {
                    if (Boolean.TRUE.equals(a.get("primary"))) {
                        return -1;
                    }

                    return 1;
                })
                .map(m -> Objects.toString(m.get(serverAttributes.emailAttribute())))
                .findFirst()
                .orElse(null);

        return Optional.ofNullable(email);
    }

}
