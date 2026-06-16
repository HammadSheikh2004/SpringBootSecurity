package com.mhis.springbootsecurity.controller;

import com.mhis.springbootsecurity.DTOs.AuthResponse;
import com.mhis.springbootsecurity.DTOs.LoginDTO;
import com.mhis.springbootsecurity.DTOs.RefreshTokenRequest;
import com.mhis.springbootsecurity.DTOs.UserDTO;
import com.mhis.springbootsecurity.helper.ApiResponse;
import com.mhis.springbootsecurity.services.AuthService;
import com.mhis.springbootsecurity.entity.Registration;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<ApiResponse<String>> logout(@RequestBody RefreshTokenRequest request) {

        authService.logout(request.getRefreshToken());

        return ResponseEntity.ok(
                new ApiResponse<>(true, "Logout successful", null)
        );
    }

    @GetMapping("/userById/{id}")
    public ResponseEntity<ApiResponse<UserDTO>> userById(@PathVariable UUID id) {

        UserDTO user = authService.userById(id);

        return ResponseEntity.ok(
                new ApiResponse<>(true, "Logout successful", user)
        );
    }

}
