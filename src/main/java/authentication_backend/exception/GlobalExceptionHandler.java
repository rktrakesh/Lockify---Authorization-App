package authentication_backend.exception;

import authentication_backend.dto.AuthenticationError;
import authentication_backend.dto.ErrorResponse;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.IOException;
import java.time.OffsetDateTime;

@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException (ResourceNotFoundException exception) {
        logger.error("EXCEPTION_001_RESOURCE_NOT_FOUND: Resource not found - error: {}", exception.getMessage());
        ErrorResponse errorResponse = new ErrorResponse(exception.getMessage(), HttpStatus.NOT_FOUND);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException (IllegalArgumentException exception) {
        logger.error("EXCEPTION_002_ILLEGAL_ARGUMENT: Invalid argument provided - error: {}", exception.getMessage());
        ErrorResponse errorResponse = new ErrorResponse(exception.getMessage(), HttpStatus.BAD_REQUEST);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler({
            BadCredentialsException.class,
            UsernameNotFoundException.class,
            CredentialsExpiredException.class,
            DisabledException.class
    })
    public ResponseEntity<AuthenticationError> handleBadCredentialsException (Exception exception, HttpServletRequest request) {
        logger.warn("EXCEPTION_003_AUTHENTICATION_FAILED: Authentication failed - exceptionType: {}, error: {}", exception.getClass().getSimpleName(), exception.getMessage());
        AuthenticationError error = new AuthenticationError(
                exception.getMessage(),
                "Bad credentials",
                request.getRequestURI(),
                OffsetDateTime.now()
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(JwtException.class)
    public void handleJwtException (JwtException exception, HttpServletResponse response) throws IOException {
        logger.error("EXCEPTION_004_JWT_EXCEPTION: JWT processing error - error: {}", exception.getMessage());
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getOutputStream().println("{ \"error\": \"" + exception.getMessage() + "\" }");
    }

    @ExceptionHandler(MalformedJwtException.class)
    public void handleMalformedJwtException (MalformedJwtException exception, HttpServletResponse response) throws IOException {
        logger.error("EXCEPTION_005_MALFORMED_JWT: Malformed JWT token - error: {}", exception.getMessage());
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getOutputStream().println("{ \"error\": \"" + exception.getMessage() + "\" }");
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponse> handleIllegalStateException (IllegalStateException exception, HttpServletRequest request) {
        logger.error("EXCEPTION_006_ILLEGAL_STATE: Illegal state occurred - error: {}", exception.getMessage());
        ErrorResponse errorResponse = new ErrorResponse(exception.getMessage(), HttpStatus.CONFLICT);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleHttpMessageNotReadableException (HttpMessageNotReadableException exception, HttpServletRequest request) {
        logger.error("EXCEPTION_007_JSON_PARSE_ERROR: JSON deserialization failed - error: {}, requestUri: {}", exception.getMessage(), request.getRequestURI());
        ErrorResponse errorResponse = new ErrorResponse("Invalid request body format: " + exception.getMostSpecificCause().getMessage(), HttpStatus.BAD_REQUEST);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

}
