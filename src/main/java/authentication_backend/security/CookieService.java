package authentication_backend.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
@Getter
public class CookieService {

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookiePath;
    private final String cookieDomain;
    private final String cookieSameSite;

    public CookieService(@Value("${security.jwt.refresh-token-cookie-name}") String refreshTokenCookieName,
                         @Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly,
                         @Value("${security.jwt.cookie-secure}") boolean cookieSecure,
                         @Value("${security.jwt.cookie-path}") String cookiePath,
                         @Value("${security.jwt.cookie-domain}") String cookieDomain,
                         @Value("${security.jwt.cookie-same-site}")String cookieSameSite) {
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookiePath = cookiePath;
        this.cookieDomain = cookieDomain;
        this.cookieSameSite = cookieSameSite;
    }

    // create method to attach cookie to response
    public void attachRefreshCookieToResponse(String refreshToken, HttpServletResponse response, int maxAge) {
        var build = ResponseCookie.from(refreshTokenCookieName, refreshToken)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .path(cookiePath)
                .sameSite(cookieSameSite)
                .maxAge(maxAge);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            build.domain(cookieDomain);
        }
        ResponseCookie responseCookie = build.build();
        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());

    }

     // create method to clear cookie from response
    public void clearRefreshCookie(HttpServletResponse response) {
        var build = ResponseCookie.from(refreshTokenCookieName, "")
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .path(cookiePath)
                .sameSite(cookieSameSite)
                .maxAge(0);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            build.domain(cookieDomain);
        }
        ResponseCookie responseCookie = build.build();
        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
    }

    //add new store header method to response
    public void attachNoStoreHeaderToResponse(HttpServletResponse response) {
        response.addHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Pragma", "no-cache");
    }

}
