package authentication_backend.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenResponse {
    private String accessToken;
    private String tokenType;
    private long expiresIn;
    private UserDto userDto;
    private String refreshToken;
}
