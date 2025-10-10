package com.hayden.authorization.oauth2;

import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserRepository;
import com.hayden.utilitymodule.stream.StreamUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class SocialRegistrationOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final OAuth2AuthorizedClientService authorizationService;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final CdcUserRepository cdcUserRepository;
    private final PasswordEncoder passwordEncoder;


    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest req) throws OAuth2AuthenticationException {
        OAuth2User remote = delegate.loadUser(req);
        var email = tryGetEmail(req, remote);
        email.ifPresent(u -> remote.getAttributes().put("email", u));
        String provider = req.getClientRegistration()
                             .getRegistrationId();
        String externalId = remote.getName();
        var accessToken = req.getAccessToken()
                             .getTokenValue();
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId(externalId, provider);
        var createUpdate = cdcUserRepository.findById(userId)
                                            .map(user -> {
                                                user.setAuthorizationCode(accessToken);
                                                if (user.getEmail() == null)
                                                    email.ifPresent(user::setEmail);
                                                return cdcUserRepository.save(user);
                                            })
                                            .orElseGet(() -> {
                                                return cdcUserRepository.save(
                                                        CdcUser.builder()
                                                               .authorities(new ArrayList<>())
                                                               .metadata(remote.getAttributes())
                                                               .principalId(userId)
                                                               .email(email.orElse(null))
                                                               .password(passwordEncoder.encode(accessToken))
                                                               .authorizationCode(accessToken)
                                                               .build());
                                            });


        return createUpdate;
    }

    private static Optional<String> tryGetEmail(OAuth2UserRequest req, OAuth2User remote) {
        try {
            if ("github".equals(req.getClientRegistration()
                                   .getRegistrationId())) {
                String token = req.getAccessToken()
                                  .getTokenValue();

                // Call /user/emails to get private emails
                RequestEntity<Void> request = RequestEntity
                        .get(URI.create("https://api.github.com/user/emails"))
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .build();

                ResponseEntity<List<Map<String, Object>>> resp = new RestTemplateBuilder().build()
                                                                                          .exchange(request,
                                                                                                  new ParameterizedTypeReference<>() {
                                                                                                  });

                String email = StreamUtil.toStream(resp.getBody())
                                         .filter(m -> Boolean.TRUE.equals(m.get("verified")))
                                         .sorted((a, b) -> Boolean.TRUE.equals(a.get("primary")) ? -1 : 1)
                                         .map(m -> (String) m.get("email"))
                                         .findFirst()
                                         .orElse(null);

                return Optional.ofNullable(email);
            }
        } catch (Exception e) {
            log.error("Error when requesting user email", e);
        }

        return Optional.empty();

    }

}
