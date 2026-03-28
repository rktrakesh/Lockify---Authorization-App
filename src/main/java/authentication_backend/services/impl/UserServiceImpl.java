package authentication_backend.services.impl;

import authentication_backend.dto.UserDto;
import authentication_backend.entity.Provider;
import authentication_backend.entity.User;
import authentication_backend.exception.ResourceNotFoundException;
import authentication_backend.helper.UserHelper;
import authentication_backend.repo.UserRepository;
import authentication_backend.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepo;
    private final ModelMapper mapper;

    @Override
    @Transactional
    public UserDto createNewUser(UserDto userDto) {

        if (userRepo.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException("User already exists for this email.");
        }

        User user = mapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider() != null ? userDto.getProvider() : Provider.LOCAL);
        User savedUser = userRepo.save(user);

        return mapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {
        User user = userRepo.findByEmail(email).orElseThrow(() -> new ResourceNotFoundException("User not found for given email id."));
        return mapper.map(user, UserDto.class);
    }

    @Override
    public UserDto updateUserDetails(UserDto userDto, String userId) {
        if (userDto == null) {
            throw new IllegalArgumentException("Please provide valid data.");
        }
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("Please provide valid userId");
        }
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepo.findById(uId).orElseThrow(() -> new ResourceNotFoundException("User not found for provided user Id."));
        if (userDto.getName() != null) user.setName(userDto.getName());
        if (userDto.getImage() != null) user.setImage(userDto.getImage());
        if (userDto.getProvider() != null) user.setProvider(userDto.getProvider());
        if (userDto.getPassword() != null) user.setPassword(userDto.getPassword());
        user.setEnable(userDto.isEnable());

        User newUser = userRepo.save(user);
        return mapper.map(newUser, UserDto.class);
    }

    @Override
    public String deleteUser(String userId) {
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("Please provide valid userId");
        }
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepo.findById(uId).orElseThrow(() -> new ResourceNotFoundException("User not found for provided user Id."));
        userRepo.delete(user);
        return "User deleted successfully for given user Id.";
    }

    @Override
    public UserDto getUserById(String userId) {
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("Please provide valid userId");
        }
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepo.findById(uId).orElseThrow(() -> new ResourceNotFoundException("User not found for provided user id"));
        return mapper.map(user, UserDto.class);
    }

    @Override
    public Iterable<UserDto> getAllUsers() {
        return userRepo.findAll()
                .stream()
                .map(user -> mapper.map(user, UserDto.class))
                .toList();
    }
}
