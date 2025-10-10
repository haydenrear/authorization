package com.hayden.authorization.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CdcUserDetails implements UserDetailsService {

    private final CdcUserRepository cdcUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return cdcUserRepository.findById(new CdcUser.CdcUserId(username, "github"))
                                .orElse(null);

    }

}
