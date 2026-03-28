package authentication_backend.security;

import authentication_backend.entity.Role;
import authentication_backend.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Getter

public class JWTService {

    private final SecretKey secretKey;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    public JWTService(@Value("${security.jwt.secret}") String secret,
                      @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
                      @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
                      @Value("${security.jwt.issuer}") String issuer) {

        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException("JWT secret key must not be null or empty");
        }
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    //generate access token
    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles() == null ? List.of() : user.getRoles().stream().map(Role::getName).toList();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(java.util.Date.from(now))
                .expiration(java.util.Date.from(now.plusSeconds(accessTtlSeconds)))
                .claims(Map.of(
                        "roles", roles,
                        "email", user.getEmail(),
                        "type", "access"
                ))
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    // generate refresh token
    public String generateRefreshToken(User user, String accessTokenId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(accessTokenId)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refreshTtlSeconds)))
                .claim("type", "refresh")
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    // parse token
    public Jws<Claims> parseToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token);
    }

    // validate token
    public boolean validateToken(String token) {
        Claims payload = parseToken(token).getPayload();
        return "access".equals(payload.get("type"));
    }

    public boolean validateRefreshToken(String token) {
        Claims payload = parseToken(token).getPayload();
        return "refresh".equals(payload.get("type"));
    }

    public UUID getUserId (String token) {
        Claims payload = parseToken(token).getPayload();
        return UUID.fromString(payload.getSubject());
    }

    public String getJti(String token) {
        Claims payload = parseToken(token).getPayload();
        return payload.getId();
    }

    public String getEmail(String token) {
        Claims payload = parseToken(token).getPayload();
        return payload.get("email", String.class);
    }

    public String getPayloadType(String token) {
        Claims payload = parseToken(token).getPayload();
        return payload.get("type", String.class);
    }

}
