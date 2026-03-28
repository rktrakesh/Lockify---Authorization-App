package authentication_backend.dto;

import org.springframework.http.HttpStatus;

public record ErrorResponse(
        String message,
        HttpStatus error
) {
}
