package authentication_backend.security;

import authentication_backend.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailService.class);
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername (String username) throws UsernameNotFoundException {
        logger.info("CUSTOM_UDS_001_LOAD_USER_START: Loading user details by username - username: {}", maskEmail(username));
        
        return userRepository.findByEmail(username).orElseThrow(() -> {
            logger.warn("CUSTOM_UDS_002_USER_NOT_FOUND: User not found for username - username: {}", maskEmail(username));
            return new UsernameNotFoundException("Invalid username or password!");
        });
    }
    
    private String maskEmail(String email) {
        if (email == null || email.length() < 3) return "***";
        return email.substring(0, 2) + "***@***";
    }
}
