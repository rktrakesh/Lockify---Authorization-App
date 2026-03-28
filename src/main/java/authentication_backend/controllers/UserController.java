package authentication_backend.controllers;

import authentication_backend.dto.UserDto;
import authentication_backend.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1.0/users")
@AllArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<UserDto> createNewUser (@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createNewUser(userDto));
    }

    @GetMapping
    public  ResponseEntity<Iterable<UserDto>> getAllUsers () {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDto> findUserByEmailId (@PathVariable String email) {
        return ResponseEntity.ok(userService.getUserByEmail(email));
    }

    @DeleteMapping("/delete/{userId}")
    public ResponseEntity<String> deleteUserByUserId (@PathVariable String userId) {
        return ResponseEntity.ok(userService.deleteUser(userId));
    }

    @GetMapping("/userId/{userId}")
    public ResponseEntity<UserDto> FindUserByUserId (@PathVariable String userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    @PutMapping("/update/{userId}")
    public ResponseEntity<UserDto> updateUser (@PathVariable String userId, @RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.updateUserDetails(userDto, userId));
    }

}
