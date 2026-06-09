package com.mhis.springbootsecurity.services;

import com.mhis.springbootsecurity.entity.Registration;
import com.mhis.springbootsecurity.repository.IUserRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final IUserRepository userRepository;

    public CustomUserDetailsService(IUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Registration user =
                userRepository.findByEmail(email);
        if(user == null){
            throw new UsernameNotFoundException("Email not Found");
        }

        return
                User.withUsername(user.getEmail()).password(user.getPassword()).roles(user.getRole().name()).build();
    }
}
