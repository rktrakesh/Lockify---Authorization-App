package authentication_backend.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder

@Entity
@Table(name = "roles")
public class Role {

    @Id
    @Column(name = "role_id")
    private UUID id = UUID.randomUUID();
    @Column(nullable = false, unique = true)
    private String name;

}
