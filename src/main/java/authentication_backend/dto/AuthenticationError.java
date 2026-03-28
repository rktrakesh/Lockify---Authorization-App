package authentication_backend.dto;

import lombok.*;

import java.time.OffsetDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthenticationError {

    private String message;
    private String error;
    private String path;
    private OffsetDateTime timestamp;

}
