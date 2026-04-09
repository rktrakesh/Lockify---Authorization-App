package authentication_backend.controllers;

import authentication_backend.dto.UserDto;
import authentication_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1.0/users")
@AllArgsConstructor
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;

    @PostMapping
    public ResponseEntity<UserDto> createNewUser (@RequestBody UserDto userDto) {
        logger.info("USER_CTRL_001_CREATE_USER_REQUEST: User creation endpoint called");
        UserDto createdUser = userService.createNewUser(userDto);
        logger.info("USER_CTRL_002_CREATE_USER_SUCCESS: User created successfully - userId: {}", createdUser.getId());
        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public  ResponseEntity<Iterable<UserDto>> getAllUsers () {
        logger.info("USER_CTRL_003_GET_ALL_USERS_REQUEST: Get all users endpoint called");
        Iterable<UserDto> users = userService.getAllUsers();
        logger.info("USER_CTRL_004_GET_ALL_USERS_SUCCESS: Retrieved all users");
        return ResponseEntity.ok(users);
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDto> findUserByEmailId (@PathVariable String email) {
        logger.info("USER_CTRL_005_GET_USER_BY_EMAIL_REQUEST: Get user by email endpoint called - email: {}", maskEmail(email));
        UserDto user = userService.getUserByEmail(email);
        logger.info("USER_CTRL_006_GET_USER_BY_EMAIL_SUCCESS: User found - userId: {}", user.getId());
        return ResponseEntity.ok(user);
    }

    @DeleteMapping("/delete/{userId}")
    public ResponseEntity<String> deleteUserByUserId (@PathVariable String userId) {
        logger.info("USER_CTRL_007_DELETE_USER_REQUEST: Delete user endpoint called - userId: {}", userId);
        String result = userService.deleteUser(userId);
        logger.info("USER_CTRL_008_DELETE_USER_SUCCESS: User deleted successfully - userId: {}", userId);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/userId/{userId}")
    public ResponseEntity<UserDto> FindUserByUserId (@PathVariable String userId) {
        logger.info("USER_CTRL_009_GET_USER_BY_ID_REQUEST: Get user by ID endpoint called - userId: {}", userId);
        UserDto user = userService.getUserById(userId);
        logger.info("USER_CTRL_010_GET_USER_BY_ID_SUCCESS: User found - userId: {}", user.getId());
        return ResponseEntity.ok(user);
    }

    @PutMapping("/update/{userId}")
    public ResponseEntity<UserDto> updateUser (@PathVariable String userId, @RequestBody UserDto userDto) {
        logger.info("USER_CTRL_011_UPDATE_USER_REQUEST: Update user endpoint called - userId: {}", userId);
        UserDto updatedUser = userService.updateUserDetails(userDto, userId);
        logger.info("USER_CTRL_012_UPDATE_USER_SUCCESS: User updated successfully - userId: {}", userId);
        return ResponseEntity.status(HttpStatus.OK).body(updatedUser);
    }
    
    private String maskEmail(String email) {
        if (email == null || email.length() < 3) return "***";
        return email.substring(0, 2) + "***@***";
    }
}
