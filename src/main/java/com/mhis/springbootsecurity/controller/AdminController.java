package com.mhis.springbootsecurity.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin Controller", description = "Admin related APIs")
public class AdminController {
    @GetMapping("/admin")
    public String Admin(){
        return "Hello From Admin Controller";
    }
}
