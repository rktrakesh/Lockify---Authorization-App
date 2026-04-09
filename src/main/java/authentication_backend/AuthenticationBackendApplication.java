package authentication_backend;

import authentication_backend.config.AppConstrants;
import authentication_backend.entity.Role;
import authentication_backend.repo.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@RequiredArgsConstructor
public class AuthenticationBackendApplication implements CommandLineRunner {

	private static final Logger log = LoggerFactory.getLogger(AuthenticationBackendApplication.class);
	private final RoleRepository roleRepository;

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationBackendApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		roleRepository.findByName("ROLE_"+AppConstrants.ADMIN_ROLE).ifPresentOrElse(role -> {
			log.info("ROLE_001_ADMIN_ROLE_EXISTS: Admin role already exists in the database - roleId: {}", role.getId());
		}, () -> {
			Role role = new Role();
			role.setName("ROLE_"+AppConstrants.ADMIN_ROLE);
			roleRepository.save(role);
		});

		roleRepository.findByName("ROLE_"+AppConstrants.GUEST_ROLE).ifPresentOrElse(role -> {
			log.info("ROLE_001_GUEST_ROLE_EXISTS: Guest role already exists in the database - roleId: {}", role.getId());
		}, () -> {
			Role role = new Role();
			role.setName("ROLE_"+AppConstrants.GUEST_ROLE);
			roleRepository.save(role);
		});
	}
}
