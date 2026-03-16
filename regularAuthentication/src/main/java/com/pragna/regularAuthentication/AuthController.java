package com.pragna.regularAuthentication;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    private final WebClient profileClient = WebClient.builder()
            .baseUrl("http://localhost:9093")
            .build();

    public AuthController(UserService userService,
                          AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    /* ── Register ────────────────────────────────────────── */
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(
            @RequestBody RegisterRequest req) {

        if (req.getUsername() == null || req.getUsername().isBlank())
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "Username is required"));
        if (req.getPassword() == null || req.getPassword().length() < 6)
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "Password must be at least 6 characters"));
        if (req.getEmail() == null || !req.getEmail().contains("@"))
            return ResponseEntity.badRequest()
                    .body(Map.of("message", "Valid email is required"));

        User user = new User();
        user.setUsername(req.getUsername().trim());
        user.setPassword(req.getPassword());
        user.setEmail(req.getEmail().trim().toLowerCase());
        user.setDisplayName(req.getUsername().trim());
        userService.registerUser(user, req.getRole());

        Map<String, String> res = new HashMap<>();
        res.put("message",  "User registered successfully");
        res.put("username", req.getUsername());
        res.put("role",     req.getRole());
        return ResponseEntity.status(HttpStatus.CREATED).body(res);
    }

    /* ── Login ───────────────────────────────────────────── */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody LoginRequest req,
            HttpServletResponse httpResponse) {
        try {
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    req.getUsername(), req.getPassword())
            );

            boolean isAdmin = auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
            String role     = isAdmin ? "ROLE_ADMIN" : "ROLE_USER";
            String username = auth.getName();

            // Fetch user for email/displayName
            User user = userService.findByUsername(username);
            String email       = user != null && user.getEmail() != null
                                 ? user.getEmail() : "";
            String displayName = user != null && user.getDisplayName() != null
                                 ? user.getDisplayName() : username;

            Map<String, Object> profileResponse =
                    callProfileService(username, displayName, email, "",
                            role, "local", "regular", httpResponse);

            profileResponse.put("message", "Login successful");
            return ResponseEntity.ok(profileResponse);

        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "Invalid username or password"));
        }
    }

    /* ── OAuth2 user persistence ─────────────────────────── */
    /**
     * POST /api/auth/oauth2/save-user
     * Called by OAuth2SuccessHandler to persist OAuth2 users to DB.
     * Internal endpoint — not exposed via gateway.
     */
    @PostMapping("/oauth2/save-user")
    public ResponseEntity<Map<String, Object>> saveOAuthUser(
            @RequestBody Map<String, String> req) {
        try {
            User saved = userService.saveOAuthUser(
                    req.get("provider"),
                    req.get("providerId"),
                    req.get("name"),
                    req.get("email"),
                    req.get("avatarUrl")
            );
            return ResponseEntity.ok(Map.of(
                    "username", saved.getUsername(),
                    "email",    saved.getEmail() != null ? saved.getEmail() : "",
                    "id",       saved.getId()
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", e.getMessage()));
        }
    }

    /* ── Logout ──────────────────────────────────────────── */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse response) {
        try {
            profileClient.post()
                    .uri("/api/profile/logout")
                    .retrieve()
                    .toBodilessEntity()
                    .block();
        } catch (Exception e) { /* cookie expires anyway */ }

        response.addHeader("Set-Cookie",
                "refreshToken=; Path=/api/profile/refresh; HttpOnly; Max-Age=0; SameSite=Strict");
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    /* ── Profile service call ────────────────────────────── */
    @SuppressWarnings("unchecked")
    private Map<String, Object> callProfileService(
            String username, String displayName, String email,
            String avatar, String role, String provider, String loginMethod,
            HttpServletResponse httpResponse) {
        try {
            Map<String, String> body = new HashMap<>();
            body.put("username",    username);
            body.put("displayName", displayName);
            body.put("email",       email);
            body.put("avatar",      avatar);
            body.put("role",        role);
            body.put("provider",    provider);
            body.put("loginMethod", loginMethod);

            var clientResponse = profileClient.post()
                    .uri("/api/profile/token")
                    .bodyValue(body)
                    .exchangeToMono(response -> {
                        response.headers().asHttpHeaders()
                                .getValuesAsList("Set-Cookie")
                                .forEach(v -> httpResponse.addHeader("Set-Cookie", v));
                        return response.bodyToMono(Map.class);
                    })
                    .block();

            if (clientResponse != null)
                return new HashMap<>(clientResponse);

        } catch (WebClientResponseException e) {
            System.err.println("[AUTH] Profile service error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("[AUTH] Profile service unreachable: " + e.getMessage());
        }
        return Map.of("message", "Profile service unavailable, please retry");
    }
}