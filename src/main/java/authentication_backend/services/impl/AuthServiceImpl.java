package authentication_backend.services.impl;

import authentication_backend.dto.UserDto;
import authentication_backend.helper.Validator;
import authentication_backend.services.AuthService;
import authentication_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    public final UserService userService;
    public final Validator validator;
    public final PasswordEncoder passwordEncoder;

    @Override
    public UserDto resister(UserDto userDto) {
        if (userDto == null) {
            logger.warn("AUTH_001_REGISTER_NULL_DATA: Registration attempt with null user data");
            throw new IllegalArgumentException("Please provide valid data.");
        }
        
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            logger.warn("AUTH_002_REGISTER_EMPTY_EMAIL: Registration attempt with empty email");
            throw new IllegalArgumentException("Please provide email id.");
        }
        
        if (!validator.isValidEmail(userDto.getEmail())) {
            logger.warn("AUTH_003_REGISTER_INVALID_EMAIL_FORMAT: Registration attempt with invalid email format - email: {}", maskEmail(userDto.getEmail()));
            throw new IllegalArgumentException("Please provide valid email id.");
        }
        
        if (!validator.isValidPassword(userDto.getPassword())) {
            logger.warn("AUTH_004_REGISTER_WEAK_PASSWORD: Registration attempt with weak password for email: {}", maskEmail(userDto.getEmail()));
            throw new IllegalArgumentException("Password must be 8+ chars with 1 upper, 1 lower, 1 digit, and 1 special char.");
        }
        
        logger.info("AUTH_005_REGISTER_PASSWORD_ENCODING: Starting password encoding for email: {}", maskEmail(userDto.getEmail()));
        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        
        logger.info("AUTH_006_REGISTER_USER_CREATION_START: Initiating user creation for email: {}", maskEmail(userDto.getEmail()));
        UserDto newUser = userService.createNewUser(userDto);
        
        logger.info("AUTH_007_REGISTER_SUCCESS: User registration completed successfully - userId: {}", newUser.getId());
        return newUser;
    }
    
    private String maskEmail(String email) {
        if (email == null || email.length() < 3) return "***";
        return email.substring(0, 2) + "***@***";
    }
}
