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

    /**
     * GET /api/admin/dashboard
     * Only ROLE_ADMIN can access. Spring Security returns 403 automatically
     * for any other role — no manual role check needed.
     */
    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> adminDashboard(Principal principal) {
        return Map.of(
                "message",  "Welcome to Admin Dashboard",
                "username", principal.getName(),
                "role",     "ADMIN"
        );
    }

    /**
     * GET /api/user/dashboard
     * Both ROLE_USER and ROLE_ADMIN can access.
     */
    @GetMapping("/user/dashboard")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Map<String, Object> userDashboard(Principal principal) {
        return Map.of(
                "message",  "Welcome to User Dashboard",
                "username", principal.getName()
        );
    }
}