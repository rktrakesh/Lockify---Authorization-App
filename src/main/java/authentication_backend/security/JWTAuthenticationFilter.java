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
        logger.info("doFilterInternal :: Processing JWT authentication for request: {}", request.getRequestURI());
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer")) {
            logger.info("Bearer token: {}", authHeader);
            String token = authHeader.substring(7).trim().replaceAll("\\s", "");
            logger.info("Parsing JWT token: {}", token);
            try {

                if (!jwtService.validateToken(token)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                Jws<Claims> claimsJws = jwtService.parseToken(token);
                Claims claims = claimsJws.getPayload();
                String userId = claims.getSubject();
                UUID uuid = UserHelper.parseUUID(userId);
                if (uuid == null) {
                    filterChain.doFilter(request, response);
                    return;
                }
                userRepository.findById(uuid).ifPresent(user -> {
                    if (user.isEnable()) {
                        List<GrantedAuthority> authorities = user.getRoles() == null ? List.of() : user.getRoles()
                                .stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName())).collect(Collectors.toList());
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities);
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        if (SecurityContextHolder.getContext().getAuthentication() == null) {
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                        }
                    }
                });

            } catch (ExpiredJwtException e) {
                logger.error("Expired JWT token error: {}", e.getMessage());
                request.setAttribute("error", "Token expired");
            } catch (MalformedJwtException e) {
                logger.error("JWT token error: {}", e.getMessage());
                request.setAttribute("error", "Invalid token");
            }catch (Exception e) {
                logger.error("Unexpected error in JWT authentication filter: {}", e.getMessage());
                request.setAttribute("error", "Invalid token");
            }
        }
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            logger.warn("No authentication set for request: {}", request.getRequestURI());
        }
        filterChain.doFilter(request, response);
    }
}
