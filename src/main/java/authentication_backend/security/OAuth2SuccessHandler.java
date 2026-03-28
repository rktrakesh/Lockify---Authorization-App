package authentication_backend.security;

import authentication_backend.entity.RefreshToken;
import authentication_backend.entity.User;
import authentication_backend.repo.RefreshTokenRepository;
import authentication_backend.repo.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(OAuth2SuccessHandler.class);
    private final UserRepository userRepository;
    private final JWTService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        logger.info("OAuth2 authentication successful for user: {}", authentication.getName());

        OAuth2User principalUser = (OAuth2User) authentication.getPrincipal();

        String registrationId = null;
        if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
            registrationId = oAuth2AuthenticationToken.getAuthorizedClientRegistrationId();
        }

        if (Objects.requireNonNull(registrationId).equals("google")) {
            assert principalUser != null;

            // Extract user information from the OAuth2User attributes
            String email = principalUser.getAttributes().getOrDefault("email", null).toString();
            String name = principalUser.getAttributes().getOrDefault("name", null).toString();
            String picture = principalUser.getAttributes().getOrDefault("picture", null).toString();

            User user = userRepository.findByEmail(email)
                    .orElseGet(() -> {
                        User newUser = User.builder()
                                .email(email)
                                .name(name)
                                .image(picture)
                                .enable(true)
                                .build();
                        return userRepository.save(newUser);
                    });

            // jwt token generation and response handling can be done here
            String jti = UUID.randomUUID().toString();
            RefreshToken refreshTokenObject = RefreshToken.builder()
                    .jti(jti)
                    .user(user)
                    .revoked(false)
                    .createdAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                    .build();

            refreshTokenRepository.save(refreshTokenObject);

            // generate access token and refresh token
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user, jti);

            // set refresh token in http only cookie
            cookieService.attachRefreshCookieToResponse(refreshToken, response, (int)jwtService.getRefreshTtlSeconds());
            cookieService.attachNoStoreHeaderToResponse(response);

        } else {
            throw new IllegalStateException("Unsupported OAuth2 provider: " + registrationId);
        }

        response.getWriter().write("OAuth2 authentication successful for user: " + authentication.getName());
    }
}
