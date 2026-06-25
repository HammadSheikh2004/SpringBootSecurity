package com.mhis.springbootsecurity.services;

import com.mhis.springbootsecurity.DTOs.AuthResponse;
import com.mhis.springbootsecurity.DTOs.LoginDTO;
import com.mhis.springbootsecurity.DTOs.UserDTO;
import com.mhis.springbootsecurity.DTOs.UserProfileDTO;
import com.mhis.springbootsecurity.configuration.JwtService;
import com.mhis.springbootsecurity.entity.Registration;
import com.mhis.springbootsecurity.entity.Roles;
import com.mhis.springbootsecurity.entity.Token;
import com.mhis.springbootsecurity.entity.UserProfile;
import com.mhis.springbootsecurity.repository.ITokenRepository;
import com.mhis.springbootsecurity.repository.IUserProfileRepository;
import com.mhis.springbootsecurity.repository.IUserRepository;
import com.mhis.springbootsecurity.validation.PasswordValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;


@Service
public class AuthService {

    @Autowired
    private IUserRepository userRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private ITokenRepository tokenRepository;
    @Autowired
    private IUserProfileRepository userProfileRepository;
    private String Secret;
    public AuthService(@Value("${JWT_SECRET_KEY}") String secret){
        this.Secret = secret;
    }


    public UserDTO userRegistered(UserDTO userDTO) {

        if(userRepo.existsByEmail(userDTO.getEmail())){
            throw  new RuntimeException("Email already Exists");
        }

        if(userRepo.existsByUserName(userDTO.getUserName())){
            throw new RuntimeException("Username already Exists!");
        }

        List<String> errors = PasswordValidator.validate(userDTO.getPassword());

        if (!errors.isEmpty()) {
            throw new RuntimeException(String.join(", ", errors));
        }

        if (!userDTO.getPassword().equals(userDTO.getConfirmPassword())) {
            throw new IllegalArgumentException("Password and Confirm Password do not match");
        }

        String encryptedPassword =
                passwordEncoder.encode(userDTO.getPassword());

        String encryptedConfirmPassword =
                passwordEncoder.encode(userDTO.getConfirmPassword());

        Registration registration = Registration.builder()
                .userName(userDTO.getUserName())
                .email(userDTO.getEmail())
                .password(encryptedPassword)
                .confirmPassword(encryptedConfirmPassword)
                .role(Roles.USER)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now()).build();
        Registration savedUsers = userRepo.save(registration);
        return UserDTO.builder()
                .registrationId(savedUsers.getRegistrationId())
                .userName(savedUsers.getUserName())
                .email(savedUsers.getEmail())
                .role(savedUsers.getRole())
                .password(savedUsers.getPassword())
                .confirmPassword(savedUsers.getConfirmPassword())
                .createdAt(savedUsers.getCreatedAt())
                .updatedAt(savedUsers.getUpdatedAt()).build();
    }

    public AuthResponse signin(LoginDTO loginDTO) {

        Registration user =
                userRepo.findByEmail(loginDTO.getEmail());

        if(user == null){
            throw new RuntimeException("User not found");
        }

        if(!passwordEncoder.matches(
                loginDTO.getPassword(),
                user.getPassword())) {

            throw new RuntimeException("Invalid Password");
        }

        String accessToken =
                jwtService.generateToken(
                        user.getEmail(),
                        user.getRole(),
                        user.getRegistrationId());

        String refreshToken =
                jwtService.generateRefreshToken(
                        user.getEmail(),
                        user.getRole(),
                        user.getRegistrationId());

        Token tokenEntity = new Token();

        tokenEntity.setUserName(user.getUserName());
        tokenEntity.setUserId(user.getRegistrationId());
        tokenEntity.setRefreshToken(refreshToken);
        tokenEntity.setExpiryDate(
                LocalDateTime.now().plusDays(7));
        tokenEntity.setRevoke(false);

        tokenRepository.save(tokenEntity);

        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public UserDTO userById(UUID userId){
        Registration findUser =
                userRepo.findById(userId).orElseThrow(()->new RuntimeException(
                        "User not Find!"));
        return UserDTO.builder()
                .registrationId(findUser.getRegistrationId())
                .userName(findUser.getUserName())
                .email(findUser.getEmail())
                .role(findUser.getRole())
                .password(findUser.getPassword())
                .confirmPassword(findUser.getConfirmPassword())
                .createdAt(findUser.getCreatedAt())
                .updatedAt(findUser.getUpdatedAt()).build();
    }

    public ResponseCookie getRefreshCookie(String refreshToken) {

        return ResponseCookie.from("refreshCookie", refreshToken)
                .httpOnly(true)
                .secure(false) // dev mode
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ofDays(7))
                .build();
    }

    public AuthResponse refreshToken(String refreshToken){

        Token tokenEntity =
                tokenRepository.findByRefreshToken(refreshToken)
                        .orElseThrow(() ->
                                new RuntimeException("Invalid refresh token"));

        if(tokenEntity.isRevoke()){
            throw new RuntimeException("Token revoked");
        }
        if(tokenEntity.getExpiryDate().isBefore(LocalDateTime.now())){
            throw new RuntimeException("Token expired");
        }
        Registration user =
                userRepo.findById(tokenEntity.getUserId())
                        .orElseThrow();
        String newAccessToken =
                jwtService.generateToken(
                        user.getEmail(),
                        user.getRole(),
                        user.getRegistrationId());
        return AuthResponse.builder()
                .token(newAccessToken)
                .userName(user.getUserName())
                .refreshToken(refreshToken)
                .build();
    }

    public Registration getUserFromToken(String token){
        System.out.println("TOKEN: " + token);
        Claims claims =
                Jwts.parser()
                        .setSigningKey(Secret.getBytes())
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
        System.out.println("CLAIMS: " + claims);
        UUID registrationId =
                UUID.fromString(
                        claims.get("RegistrationId", String.class)
                );
        System.out.println("REG ID: " + registrationId);
        return userRepo.findByRegistrationId(registrationId);
    }

    public void logout(String refreshToken) {

        Token tokenEntity =
                tokenRepository.findByRefreshToken(refreshToken)
                        .orElseThrow(() -> new RuntimeException("Invalid token"));

        tokenEntity.setRevoke(true);
        tokenRepository.save(tokenEntity);
    }

    public UserProfile userProfile(UserProfileDTO dto, UUID registrationId) throws IOException {

        Registration registration = userRepo.findById(registrationId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        UserProfile profile = userProfileRepository
                .findByUserRegistration_RegistrationId(registrationId)
                .orElse(new UserProfile());

        profile.setFirstName(dto.getFirstName());
        profile.setLastName(dto.getLastName());
        profile.setUserRegistration(registration);

        MultipartFile image = dto.getUserImage();
        if (image != null && !image.isEmpty()) {
            String uploads = "uploads/profile";
            Files.createDirectories(Paths.get(uploads));

            String fileName = UUID.randomUUID() + "_" + image.getOriginalFilename();
            Path path = Paths.get(uploads, fileName);

            Files.write(path, image.getBytes());

            profile.setUserImage(fileName);
        }
        return userProfileRepository.save(profile);
    }

}

