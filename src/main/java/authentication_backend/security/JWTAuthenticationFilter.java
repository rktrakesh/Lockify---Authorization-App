package authentication_backend.security;

import authentication_backend.helper.UserHelper;
import authentication_backend.repo.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    
    private final JWTService jwtService;
    private final UserRepository userRepository;
    private final Logger logger = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.info("FILTER_001_JWT_PROCESS_START: Processing JWT authentication for request: {}", request.getRequestURI());
        
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer")) {
            logger.debug("FILTER_002_BEARER_TOKEN_FOUND: Bearer token detected in Authorization header");
            
            String token = authHeader.substring(7).trim().replaceAll("\\s", "");
            logger.debug("FILTER_003_TOKEN_EXTRACTION: JWT token extracted from header");
            
            try {
                logger.debug("FILTER_004_TOKEN_VALIDATION_START: Starting JWT token validation");
                if (!jwtService.validateToken(token)) {
                    logger.warn("FILTER_005_TOKEN_VALIDATION_FAILED: JWT token validation failed - not access token type");
                    filterChain.doFilter(request, response);
                    return;
                }
                logger.info("FILTER_006_TOKEN_VALIDATION_SUCCESS: JWT token validation successful");

                logger.debug("FILTER_007_TOKEN_PARSING_START: Parsing JWT token claims");
                Jws<Claims> claimsJws = jwtService.parseToken(token);
                Claims claims = claimsJws.getPayload();
                String userId = claims.getSubject();
                logger.debug("FILTER_008_USER_ID_EXTRACTED: User ID extracted from token - userId: {}", userId);
                
                UUID uuid = UserHelper.parseUUID(userId);
                if (uuid == null) {
                    logger.warn("FILTER_009_INVALID_USER_ID_FORMAT: Invalid user ID format in token");
                    filterChain.doFilter(request, response);
                    return;
                }
                
                logger.debug("FILTER_010_USER_LOOKUP_START: Looking up user in database - userId: {}", userId);
                userRepository.findById(uuid).ifPresentOrElse(
                    user -> {
                        if (user.isEnable()) {
                            logger.info("FILTER_011_USER_FOUND_ENABLED: User found and enabled - userId: {}", user.getId());
                            List<GrantedAuthority> authorities = user.getRoles() == null ? List.of() : user.getRoles()
                                    .stream()
                                    .map(role -> {
                                        logger.debug("FILTER_012_ROLE_MAPPING: Mapping role - roleName: {}", role.getName());
                                        return new SimpleGrantedAuthority(role.getName());
                                    })
                                    .collect(Collectors.toList());
                            
                            logger.debug("FILTER_013_AUTH_TOKEN_CREATING: Creating authentication token with {} roles", authorities.size());
                            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities);
                            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                                SecurityContextHolder.getContext().setAuthentication(authentication);
                                logger.info("FILTER_014_AUTH_CONTEXT_SET: Authentication context set in SecurityHolder");
                            }
                        } else {
                            logger.warn("FILTER_015_USER_DISABLED: User found but disabled - userId: {}", user.getId());
                        }
                    },
                    () -> logger.warn("FILTER_016_USER_NOT_FOUND: User not found in database - userId: {}", userId)
                );

            } catch (ExpiredJwtException e) {
                logger.warn("FILTER_017_TOKEN_EXPIRED: JWT token has expired - error: {}", e.getMessage());
                request.setAttribute("error", "Token expired");
            } catch (MalformedJwtException e) {
                logger.warn("FILTER_018_TOKEN_MALFORMED: JWT token is malformed - error: {}", e.getMessage());
                request.setAttribute("error", "Invalid token");
            } catch (SignatureException e) {
                logger.warn("FILTER_019_TOKEN_SIGNATURE_INVALID: JWT token signature is invalid - error: {}", e.getMessage());
                request.setAttribute("error", "Invalid token");
            } catch (Exception e) {
                logger.error("FILTER_020_TOKEN_PROCESSING_ERROR: Unexpected error processing JWT token - error: {}", e.getMessage(), e);
                request.setAttribute("error", "Invalid token");
            }
        } else {
            logger.warn("FILTER_021_NO_BEARER_TOKEN: No Bearer token found in Authorization header for request: {}", request.getRequestURI());
        }
        
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            logger.warn("FILTER_022_NO_AUTH_SET: No authentication set for request: {}", request.getRequestURI());
        } else {
            logger.debug("FILTER_023_AUTH_SET: Authentication successfully set for request: {}", request.getRequestURI());
        }
        
        filterChain.doFilter(request, response);
    }
}
