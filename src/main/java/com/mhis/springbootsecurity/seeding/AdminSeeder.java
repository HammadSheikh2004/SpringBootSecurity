package com.mhis.springbootsecurity.seeding;

import com.mhis.springbootsecurity.entity.Registration;
import com.mhis.springbootsecurity.entity.Roles;
import com.mhis.springbootsecurity.repository.IUserRepository;
import com.mhis.springbootsecurity.validation.PasswordValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class AdminSeeder implements CommandLineRunner {
    private final IUserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    @Override
    public void run(String... args) throws Exception {
        String adminEmail = "admin@gmail.com";
        if(!userRepo.existsByEmail(adminEmail)){
            Registration admin = Registration.builder()
                    .userName("Admin")
                    .email(adminEmail)
                    .role(Roles.ADMIN)
                    .password(passwordEncoder.encode("Admin@12345"))
                    .confirmPassword(passwordEncoder.encode("Admin@12345"))
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build();

            userRepo.save(admin);

            System.out.println("Admin user seeded successfully!");
        }
    }
}
