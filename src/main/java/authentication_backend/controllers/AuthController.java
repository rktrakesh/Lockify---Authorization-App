package authentication_backend.controllers;

import authentication_backend.dto.*;
import authentication_backend.entity.Provider;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JWTService jwtService;
    private final ModelMapper modelMapper;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    @PostMapping("/register")
    public ResponseEntity<UserDto> resister (@RequestBody UserDto user) {
        logger.info("CTRL_001_REGISTER_REQUEST: Registration endpoint called");
        UserDto registeredUser = authService.resister(user);
        logger.info("CTRL_002_REGISTER_RESPONSE: Registration successful - userId: {}", registeredUser.getId());
        return ResponseEntity.status(HttpStatus.CREATED).body(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login (@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        User user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(() -> {
            logger.warn("CTRL_004_LOGIN_USER_NOT_FOUND: User not found during login - email: {}", maskEmail(loginRequest.getEmail()));
            return new BadCredentialsException("Invalid email or password");
        });

        logger.info("CTRL_003_LOGIN_REQUEST: Login endpoint called - email: {}", maskEmail(loginRequest.getEmail()));
        
        if (!user.isEnable()) {
            logger.warn("CTRL_005_LOGIN_USER_DISABLED: Login attempt for disabled account - userId: {}", user.getId());
            throw new DisabledException("User account is disabled");
        }

        if (user.getProvider() != null && !user.getProvider().equals(Provider.LOCAL)) {
            logger.warn("CTRL_006_LOGIN_WRONG_PROVIDER: Login attempt with wrong provider - userId: {}, provider: {}", user.getId(), user.getProvider());
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse(
                            "This account was created using " + user.getProvider() +
                                    ". Please login using " + user.getProvider()
                            , HttpStatus.UNAUTHORIZED
                    ));
        }

        logger.debug("CTRL_007_LOGIN_AUTHENTICATION_START: Starting authentication process");
        Authentication authenticate = authenticate(loginRequest);
        logger.info("CTRL_008_LOGIN_AUTHENTICATION_SUCCESS: Authentication successful - userId: {}", user.getId());

        // generating refresh token
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        
        logger.debug("CTRL_009_LOGIN_REFRESH_TOKEN_CREATING: Creating refresh token - jti: {}", jti);
        refreshTokenRepository.save(refreshToken);
        logger.info("CTRL_010_LOGIN_REFRESH_TOKEN_SAVED: Refresh token saved successfully");

        // generating access token
        logger.debug("CTRL_011_LOGIN_ACCESS_TOKEN_GENERATING: Generating access token");
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenString = jwtService.generateRefreshToken(user, refreshToken.getJti());
        logger.info("CTRL_012_LOGIN_TOKENS_GENERATED: Both tokens generated successfully");

        // attach refresh token to cookie
        cookieService.attachRefreshCookieToResponse(refreshTokenString, response, (int)jwtService.getRefreshTtlSeconds());
        cookieService.attachNoStoreHeaderToResponse(response);
        logger.debug("CTRL_013_LOGIN_COOKIE_ATTACHED: Refresh token attached to response cookie");

        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTtlSeconds())
                .userDto(modelMapper.map(user, UserDto.class))
                .refreshToken(refreshTokenString)
                .build();
        
        logger.info("CTRL_014_LOGIN_SUCCESS: Login completed successfully - userId: {}", user.getId());
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest,
            HttpServletResponse response,
            HttpServletRequest request
    ) {
        logger.info("CTRL_015_REFRESH_REQUEST: Token refresh endpoint called");
        
        String refreshToken = getRefreshTokenFromRequest(refreshTokenRequest, request).orElseThrow(() -> {
            logger.warn("CTRL_016_REFRESH_TOKEN_MISSING: Refresh token not found in request");
            return new BadCredentialsException("Refresh token is missing");
        });

        logger.debug("CTRL_017_REFRESH_TOKEN_VALIDATION_START: Starting refresh token validation");
        if (!jwtService.validateRefreshToken(refreshToken)) {
            logger.warn("CTRL_018_REFRESH_TOKEN_INVALID: Refresh token validation failed");
            throw new BadCredentialsException("Invalid refresh token");
        }
        logger.info("CTRL_019_REFRESH_TOKEN_VALIDATED: Refresh token validation successful");

        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);
        
        logger.debug("CTRL_020_REFRESH_TOKEN_LOOKUP: Looking up refresh token in database - jti: {}", jti);
        RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti).orElseThrow(() -> {
            logger.warn("CTRL_021_REFRESH_STORED_TOKEN_NOT_FOUND: Stored refresh token not found - jti: {}", jti);
            return new BadCredentialsException("Refresh token not found");
        });

        if (storedRefreshToken.isRevoked() || storedRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            logger.warn("CTRL_022_REFRESH_TOKEN_REVOKED_OR_EXPIRED: Token is revoked or expired - jti: {}", jti);
            throw new BadCredentialsException("Refresh token is revoked or expired");
        }

        if (!storedRefreshToken.getUser().getId().equals(userId)) {
            logger.warn("CTRL_023_REFRESH_TOKEN_USER_MISMATCH: Token user ID mismatch - jti: {}", jti);
            throw new BadCredentialsException("Refresh token does not belong to the user");
        }

        // rotate refresh token
        logger.debug("CTRL_024_REFRESH_TOKEN_ROTATION_START: Starting token rotation");
        storedRefreshToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        storedRefreshToken.setReplacedByToken(newJti);
        refreshTokenRepository.save(storedRefreshToken);
        logger.info("CTRL_025_REFRESH_OLD_TOKEN_REVOKED: Old token revoked and marked for replacement");

        User user = storedRefreshToken.getUser();
        RefreshToken newRefreshToken = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        
        logger.debug("CTRL_026_REFRESH_NEW_TOKEN_CREATING: Creating new refresh token");
        refreshTokenRepository.save(newRefreshToken);
        logger.info("CTRL_027_REFRESH_NEW_TOKEN_SAVED: New refresh token created and saved");

        // generating access token
        logger.debug("CTRL_028_REFRESH_ACCESS_TOKEN_GENERATING: Generating new access token");
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshTokenString = jwtService.generateRefreshToken(user, newRefreshToken.getJti());
        cookieService.attachRefreshCookieToResponse(newRefreshTokenString, response, (int)jwtService.getRefreshTtlSeconds());
        cookieService.attachNoStoreHeaderToResponse(response);
        
        logger.info("CTRL_029_REFRESH_SUCCESS: Token refresh completed successfully - userId: {}", user.getId());

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
        logger.info("CTRL_030_LOGOUT_REQUEST: Logout endpoint called");
        
        String refreshToken = getRefreshTokenFromRequest(null, request).orElse(null);
        if (refreshToken != null) {
            logger.debug("CTRL_031_LOGOUT_TOKEN_FOUND: Refresh token found in request");
            String jti = jwtService.getJti(refreshToken);
            
            RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti).orElse(null);
            if (storedRefreshToken != null) {
                logger.debug("CTRL_032_LOGOUT_TOKEN_REVOCATION: Revoking refresh token - jti: {}", jti);
                storedRefreshToken.setRevoked(true);
                refreshTokenRepository.save(storedRefreshToken);
                logger.info("CTRL_033_LOGOUT_TOKEN_REVOKED: Refresh token revoked successfully");
            }
        }
        
        cookieService.clearRefreshCookie(response);
        cookieService.attachNoStoreHeaderToResponse(response);
        logger.info("CTRL_034_LOGOUT_SUCCESS: Logout completed successfully");
        
        return ResponseEntity.noContent().build();
    }

    private Optional<String> getRefreshTokenFromRequest(RefreshTokenRequest refreshTokenRequest, HttpServletRequest request) {

        // Cookies
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (cookie.getName().equals(cookieService.getRefreshTokenCookieName())) {
                    logger.debug("CTRL_035_TOKEN_SOURCE_COOKIE: Refresh token extracted from cookie");
                    return Optional.of(cookie.getValue());
                }
            }
        }

        // Request body
        if (refreshTokenRequest != null && refreshTokenRequest.refreshToken() != null) {
            logger.debug("CTRL_036_TOKEN_SOURCE_BODY: Refresh token extracted from request body");
            return Optional.of(refreshTokenRequest.refreshToken());
        }

        // Authorization header
        if (request.getHeader("Authorization") != null && request.getHeader("Authorization").startsWith("Bearer ")) {
            logger.debug("CTRL_037_TOKEN_SOURCE_AUTH_HEADER: Refresh token extracted from Authorization header");
            return Optional.of(request.getHeader("Authorization").substring(7));
        }

        //custom header
        if (request.getHeader("X-Refresh-Token") != null) {
            logger.debug("CTRL_038_TOKEN_SOURCE_CUSTOM_HEADER: Refresh token extracted from X-Refresh-Token header");
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
    
    private String maskEmail(String email) {
        if (email == null || email.length() < 3) return "***";
        return email.substring(0, 2) + "***@***";
    }

}
