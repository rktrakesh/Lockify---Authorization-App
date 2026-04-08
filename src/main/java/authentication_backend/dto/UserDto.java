package authentication_backend.dto;

import authentication_backend.entity.Provider;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {

    private UUID id;
    private String name;
    private String email;
    private String password;
    private String image;
    private Boolean enable = true;
    private Instant createdAt = Instant.now();
    private  Instant updatedAt = Instant.now();
    private Set<RoleDto> roles = new HashSet<>();
    private Provider provider = Provider.LOCAL;

}
