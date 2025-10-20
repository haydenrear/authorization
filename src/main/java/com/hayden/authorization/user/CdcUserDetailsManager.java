package com.hayden.authorization.user;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class CdcUserDetailsManager implements UserDetailsManager {

    private final CdcUserRepository cdcUserRepository;
    private final CdcUserDetails userDetails;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void createUser(UserDetails user) {
        this.cdcUserRepository.save(CdcUser.builder()
                                           .email(user.getUsername())
                                           .authorities(user.getAuthorities()
                                                            .stream()
                                                            .map(GrantedAuthority::getAuthority)
                                                            .toList())
                                           .principalId(new CdcUser.CdcUserId(user.getUsername(), "cdc"))
                                           .password(passwordEncoder.encode(user.getPassword()))
                                           .build());
    }

    @Override
    public void updateUser(UserDetails user) {
        this.cdcUserRepository.findById(new CdcUser.CdcUserId(user.getUsername(), "cdc"))
                .ifPresentOrElse(
                        userFound -> {
                            var u = userFound.toBuilder();

                            if (user.getUsername() != null)
                                    u = u.email(user.getUsername());

                            if (user.getAuthorities() != null)
                                    u = u.authorities(user.getAuthorities()
                                            .stream()
                                            .map(GrantedAuthority::getAuthority)
                                            .toList());

                            if (user.getPassword() != null)
                                    u = u.password(passwordEncoder.encode(user.getPassword()));


                            this.cdcUserRepository.save(u.build());
                        },
                        () -> createUser(user)
                );
    }

    @Override
    public void deleteUser(String username) {
        this.cdcUserRepository.deleteById(new CdcUser.CdcUserId(username, "cdc"));
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        Optional.ofNullable(SecurityContextHolder.getContext())
                .flatMap(sc -> Optional.ofNullable(sc.getAuthentication()))
                .ifPresentOrElse(auth -> {
                    if (auth instanceof UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                            && passwordEncoder.matches(oldPassword, Objects.toString(auth.getCredentials()))) {
                        this.cdcUserRepository.findById(new CdcUser.CdcUserId(auth.getName(), "cdc"))
                                .ifPresentOrElse(
                                        user -> {
                                            user.setPassword(passwordEncoder.encode(newPassword));
                                            this.cdcUserRepository.save(user);
                                        },
                                        () -> log.error("Attempted to change password for user {} that did not exist.", auth.getName()));
                    } else {
                        log.error("Attempted to change password for authentication type: {}", auth.getClass().getName());
                    }
                    if (auth.getCredentials() == null) {
                        log.error("Attempted to change password for user that had no credentials.");
                    }
                }, () -> {
                    log.error("Attempted to change password for user not found.");
                });

    }

    @Override
    public boolean userExists(String username) {
        return cdcUserRepository.existsById(new CdcUser.CdcUserId(username, "cdc"));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDetails.loadUserByUsername(username);
    }
}
