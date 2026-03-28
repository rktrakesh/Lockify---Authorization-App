package authentication_backend.services.impl;

import authentication_backend.dto.UserDto;
import authentication_backend.helper.Validator;
import authentication_backend.services.AuthService;
import authentication_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    public final UserService userService;
    public final Validator validator;
    public final PasswordEncoder passwordEncoder;

    @Override
    public UserDto resister(UserDto userDto) {
        if (userDto == null) {
            throw new IllegalArgumentException("Please provide valid data.");
        }
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException("Please provide email id.");
        }
        if (!validator.isValidEmail(userDto.getEmail())) {
            throw new IllegalArgumentException("Please provide valid email id.");
        }
        if (!validator.isValidPassword(userDto.getPassword())) {
            throw new IllegalArgumentException("Password must be 8+ chars with 1 upper, 1 lower, 1 digit, and 1 special char.");
        }
        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        UserDto newUser = userService.createNewUser(userDto);
        return newUser;
    }
}
