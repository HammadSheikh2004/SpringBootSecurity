package com.mhis.springbootsecurity.controller;

import com.mhis.springbootsecurity.DTOs.*;
import com.mhis.springbootsecurity.entity.UserProfile;
import com.mhis.springbootsecurity.helper.ApiResponse;
import com.mhis.springbootsecurity.services.AuthService;
import com.mhis.springbootsecurity.entity.Registration;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController()
@RequestMapping("/api/auth")

public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/createUser")
    public ResponseEntity<ApiResponse<UserDTO>> CreateUser(@Valid @RequestBody UserDTO userDTO){
       try {
           UserDTO result = authService.userRegistered(userDTO);
           ApiResponse<UserDTO> response = new ApiResponse<>(true, "User Create " +
                   "Successfully!", result);
           return ResponseEntity.status(HttpStatus.OK).body(response);
       } catch (RuntimeException e) {
           ApiResponse<UserDTO> response =
                   new ApiResponse<>(false, e.getMessage(), null);

           return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
       }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> Login(@Valid @RequestBody LoginDTO loginDTO){
        try {
            AuthResponse result = authService.signin(loginDTO);
            ResponseCookie refreshCookie =
                    authService.getRefreshCookie(result.getRefreshToken());
            ApiResponse<AuthResponse> response = new ApiResponse<>(true, "Login Successfully!", result);
            return ResponseEntity.status(HttpStatus.OK).header(HttpHeaders.SET_COOKIE, refreshCookie.toString()).body(response);
        } catch (RuntimeException e) {
            ApiResponse<AuthResponse> response =
                    new ApiResponse<>(false, e.getMessage(), null);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<ApiResponse<AuthResponse>> RefreshToken(@Valid @RequestBody RefreshTokenRequest request){
        AuthResponse result =
                authService.refreshToken(request.getRefreshToken());

        ApiResponse<AuthResponse> response =
                new ApiResponse<>(true,
                        "Token refreshed successfully",
                        result);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getCurrentUser(
            @CookieValue(value = "refreshCookie", required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(
                            false,
                            "No refresh token cookie found"
                    ));
        }
        try {

            Registration user = authService.getUserFromToken(refreshToken);

            Map<String, Object> userData = new HashMap<>();
            userData.put("registrationId", user.getRegistrationId());
            userData.put("userName", user.getUserName());
            userData.put("email", user.getEmail());
            userData.put("role", user.getRole());
            return ResponseEntity.ok(
                    new ApiResponse<>(
                            true,
                            "User fetched successfully",
                            userData
                    )
            );
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(
                            false,
                            "Invalid or expired token"
                    ));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(
            @CookieValue("refreshCookie") String refreshToken,
            HttpServletResponse response) {

        authService.logout(refreshToken);

        Cookie cookie = new Cookie("refreshCookie", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);

        response.addCookie(cookie);

        return ResponseEntity.ok(
                new ApiResponse<>(true, "Logout successful", null)
        );
    }

    @GetMapping("/userById/{id}")
    public ResponseEntity<ApiResponse<UserDTO>> userById(@PathVariable UUID id) {

        UserDTO user = authService.userById(id);

        return ResponseEntity.ok(
                new ApiResponse<>(true, "User Find", user)
        );
    }

    @PutMapping(value = "/update", consumes =
            MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> update(
            @ModelAttribute UserProfileDTO dto,
            @RequestParam("id") UUID id
    ) throws IOException {

        return ResponseEntity.ok(
                authService.userProfile(dto, id)
        );
    }
}
