package authentication_backend.controllers;

import authentication_backend.dto.LoginRequest;
import authentication_backend.dto.RefreshTokenRequest;
import authentication_backend.dto.TokenResponse;
import authentication_backend.dto.UserDto;
import authentication_backend.entity.RefreshToken;
import authentication_backend.entity.User;
import authentication_backend.repo.RefreshTokenRepository;
import authentication_backend.repo.UserRepository;
import authentication_backend.security.CookieService;
import authentication_backend.security.JWTService;
import authentication_backend.services.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1.0/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JWTService jwtService;
    private final ModelMapper modelMapper;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    @PostMapping("/register")
    public ResponseEntity<UserDto> resister (@RequestBody UserDto user) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.resister(user));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login (@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        Authentication authenticate = authenticate(loginRequest);
        User user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
        if (!user.isEnable()) {
            throw new DisabledException("User account is disabled");
        }

        // generating refresh token
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshToken);

        // generating access token
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenString = jwtService.generateRefreshToken(user, refreshToken.getJti());

        // attach refresh token to cookie
        cookieService.attachRefreshCookieToResponse(refreshTokenString, response, (int)jwtService.getRefreshTtlSeconds());
        cookieService.attachNoStoreHeaderToResponse(response);

        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTtlSeconds())
                .userDto(modelMapper.map(user, UserDto.class))
                .refreshToken(refreshTokenString)
                .build();
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest,
            HttpServletResponse response,
            HttpServletRequest request
    ) {
        String refreshToken = getRefreshTokenFromRequest(refreshTokenRequest, request).orElseThrow(() -> new BadCredentialsException("Refresh token is missing"));

        if (!jwtService.validateRefreshToken(refreshToken)) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);
        RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti).orElseThrow(() -> new BadCredentialsException("Refresh token not found"));

        if (storedRefreshToken.isRevoked() || storedRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token is revoked or expired");
        }

        if (!storedRefreshToken.getUser().getId().equals(userId)) {
            throw new BadCredentialsException("Refresh token does not belong to the user");
        }

        // rotate refresh token
        storedRefreshToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        storedRefreshToken.setReplacedByToken(newJti);
        refreshTokenRepository.save(storedRefreshToken);

        User user = storedRefreshToken.getUser();
        RefreshToken newRefreshToken = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(newRefreshToken);

        // generating access token
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshTokenString = jwtService.generateRefreshToken(user, newRefreshToken.getJti());
        cookieService.attachRefreshCookieToResponse(newRefreshTokenString, response, (int)jwtService.getRefreshTtlSeconds());
        cookieService.attachNoStoreHeaderToResponse(response);

        return ResponseEntity.ok(TokenResponse.builder()
                .accessToken(newAccessToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTtlSeconds())
                .userDto(modelMapper.map(user, UserDto.class))
                .refreshToken(newRefreshTokenString)
                .build());

    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = getRefreshTokenFromRequest(null, request).orElse(null);
        if (refreshToken != null) {
            String jti = jwtService.getJti(refreshToken);
            RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti).orElse(null);
            if (storedRefreshToken != null) {
                storedRefreshToken.setRevoked(true);
                refreshTokenRepository.save(storedRefreshToken);
            }
        }
        cookieService.clearRefreshCookie(response);
        cookieService.attachNoStoreHeaderToResponse(response);
        return ResponseEntity.noContent().build();
    }

    private Optional<String> getRefreshTokenFromRequest(RefreshTokenRequest refreshTokenRequest, HttpServletRequest request) {

        // Cookies
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (cookie.getName().equals(cookieService.getRefreshTokenCookieName())) {
                    return Optional.of(cookie.getValue());
                }
            }
        }

        // Request body
        if (refreshTokenRequest != null && refreshTokenRequest.refreshToken() != null) {
            return Optional.of(refreshTokenRequest.refreshToken());
        }

        // Authorization header
        if (request.getHeader("Authorization") != null && request.getHeader("Authorization").startsWith("Bearer ")) {
            return Optional.of(request.getHeader("Authorization").substring(7));
        }

        //custom header
        if (request.getHeader("X-Refresh-Token") != null) {
            return Optional.of(request.getHeader("X-Refresh-Token"));
        }

        return Optional.empty();
    }

    private Authentication authenticate(LoginRequest loginRequest) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );
    }

}
