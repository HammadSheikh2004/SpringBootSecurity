package com.mhis.springbootsecurity.controller;

import com.mhis.springbootsecurity.DTOs.AuthResponse;
import com.mhis.springbootsecurity.DTOs.LoginDTO;
import com.mhis.springbootsecurity.DTOs.RefreshTokenRequest;
import com.mhis.springbootsecurity.DTOs.UserDTO;
import com.mhis.springbootsecurity.helper.ApiResponse;
import com.mhis.springbootsecurity.services.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
            ApiResponse<AuthResponse> response = new ApiResponse<>(true, "Login Successfully!", result);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (RuntimeException e) {
            ApiResponse<AuthResponse> response =
                    new ApiResponse<>(false, e.getMessage(), null);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @PostMapping("/refresToken")
    public ResponseEntity<ApiResponse<AuthResponse>> RefreshToken(@Valid @RequestBody RefreshTokenRequest request){
        AuthResponse result =
                authService.refreshToken(request.getRefreshToken());

        ApiResponse<AuthResponse> response =
                new ApiResponse<>(true,
                        "Token refreshed successfully",
                        result);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(@RequestBody RefreshTokenRequest request) {

        authService.logout(request.getRefreshToken());

        return ResponseEntity.ok(
                new ApiResponse<>(true, "Logout successful", null)
        );
    }
}
