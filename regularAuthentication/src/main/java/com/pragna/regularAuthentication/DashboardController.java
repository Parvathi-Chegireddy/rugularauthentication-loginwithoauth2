package com.pragna.regularAuthentication;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DashboardController {

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> adminDashboard(Principal principal) {
        return Map.of(
                "message",  "Welcome to Admin Dashboard",
                "username", principal.getName(),
                "role",     "ADMIN"
        );
    }

    @GetMapping("/user/dashboard")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Map<String, Object> userDashboard(Principal principal) {
        return Map.of(
                "message",  "Welcome to User Dashboard",
                "username", principal.getName()
        );
    }
}
