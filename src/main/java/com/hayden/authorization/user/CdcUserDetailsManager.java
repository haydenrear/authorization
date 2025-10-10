package com.hayden.authorization.user;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

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
                                           .principalId(new CdcUser.CdcUserId(user.getUsername(), "github"))
                                           .password(passwordEncoder.encode(user.getPassword()))
                                           .build());
    }

    @Override
    public void updateUser(UserDetails user) {
    }

    @Override
    public void deleteUser(String username) {
        this.cdcUserRepository.deleteById(new CdcUser.CdcUserId(username, "github"));

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public boolean userExists(String username) {
        throw new RuntimeException("Not implemented");
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDetails.loadUserByUsername(username);
    }
}
