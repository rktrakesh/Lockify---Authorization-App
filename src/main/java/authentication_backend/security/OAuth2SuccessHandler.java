package authentication_backend.security;

import authentication_backend.entity.Provider;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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
    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @Value("${app.auth.frontend.success-redirect-url}")
    private String frontendSuccessUrl;

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

        // crete a new user if not exist in database, otherwise return existing user
        User user;

        // Registering Google OAuth2 provider
        if (Objects.requireNonNull(registrationId).equals("google")) {
            logger.info("Google OAuth2 authentication successful for user: {}", authentication.getName());
            assert principalUser != null;

            // Extract user information from the OAuth2User attributes
            String email = principalUser.getAttributes().getOrDefault("email", null).toString();
            String name = principalUser.getAttributes().getOrDefault("name", null).toString();
            String picture = principalUser.getAttributes().getOrDefault("picture", null).toString();

            user = userRepository.findByEmail(email)
                    .orElseGet(() -> {
                        User newUser = User.builder()
                                .email(email)
                                .name(name)
                                .image(picture)
                                .enable(true)
                                .provider(Provider.GOOGLE)
                                .build();
                        return userRepository.save(newUser);
                    });

        // Registering GitHub OAuth2 provider
        } else if (registrationId.equals("github")) {
            logger.info("GitHub OAuth2 authentication successful for user: {}", authentication.getName());
            assert principalUser != null;

            // Extract user information from the OAuth2User attributes
            OAuth2AuthorizedClient client =
                    oAuth2AuthorizedClientService.loadAuthorizedClient(
                            registrationId,
                            authentication.getName()
                    );

            // some github accounts may not have public email,
            // in that case we can use the primary email from the list of emails returned by the API,
            // if there is no primary email we can use a dummy email with the username and a local domain
            String accessToken = client.getAccessToken().getTokenValue();
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            HttpEntity<?> entity = new HttpEntity<>(headers);
            ResponseEntity<List<Map<String, Object>>> responseBody =
                    restTemplate.exchange(
                            "https://api.github.com/user/emails",
                            HttpMethod.GET,
                            entity,
                            new ParameterizedTypeReference<>() {
                            }
                    );

            List<Map<String, Object>> emails = responseBody.getBody();

            String email;
            String name = principalUser.getAttributes().getOrDefault("login", null).toString();
            String picture = principalUser.getAttributes().getOrDefault("avatar_url", null).toString();

            assert emails != null;
            if (emails.isEmpty()) {
                email = name + "@github.local";
            } else {

                email = emails.stream()
                        .filter(e -> Boolean.TRUE.equals(e.get("primary")))
                        .map(e -> e.get("email").toString())
                        .findFirst()
                        .orElse(null);
            }
            user = userRepository.findByEmail(email)
                    .orElseGet(() -> {
                        User newUser = User.builder()
                                .email(email)
                                .name(name)
                                .image(picture)
                                .enable(true)
                                .provider(Provider.GITHUB)
                                .build();
                        return userRepository.save(newUser);
                    });

        } else {
            throw new IllegalStateException("Unsupported OAuth2 provider: " + registrationId);
        }

        // for same mailId change revoke status true in refresh_tokens
        UUID id = user.getId();
        List<RefreshToken> existingTokens = refreshTokenRepository.findByUserIdAndRevokedFalse(id);
        existingTokens.forEach(token -> token.setRevoked(true));
        refreshTokenRepository.saveAll(existingTokens);

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
        cookieService.attachRefreshCookieToResponse(refreshToken, response, (int) jwtService.getRefreshTtlSeconds());
        cookieService.attachNoStoreHeaderToResponse(response);

        response.sendRedirect(frontendSuccessUrl);
    }
}
