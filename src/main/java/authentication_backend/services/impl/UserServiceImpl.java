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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepo;
    private final ModelMapper mapper;

    @Override
    @Transactional
    public UserDto createNewUser(UserDto userDto) {

        if (userRepo.existsByEmail(userDto.getEmail())) {
            logger.warn("USER_001_DUPLICATE_EMAIL: Attempted user creation with existing email - email: {}", maskEmail(userDto.getEmail()));
            throw new IllegalArgumentException("User already exists for this email.");
        }

        logger.info("USER_002_CREATE_NEW_USER_START: Starting user creation for email: {}", maskEmail(userDto.getEmail()));

        User user = mapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider() != null ? userDto.getProvider() : Provider.LOCAL);
        
        logger.debug("USER_003_USER_ENTITY_MAPPED: User entity mapped successfully - provider: {}", user.getProvider());
        
        User savedUser = userRepo.save(user);

        logger.info("USER_004_CREATE_NEW_USER_SUCCESS: User created successfully - userId: {}, provider: {}", savedUser.getId(), savedUser.getProvider());

        return mapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {
        logger.debug("USER_005_GET_USER_BY_EMAIL_START: Fetching user by email");
        
        User user = userRepo.findByEmail(email).orElseThrow(() -> {
            logger.warn("USER_006_USER_NOT_FOUND_BY_EMAIL: User not found for given email");
            return new ResourceNotFoundException("User not found for given email id.");
        });
        
        logger.info("USER_007_GET_USER_BY_EMAIL_SUCCESS: User found successfully - userId: {}", user.getId());
        return mapper.map(user, UserDto.class);
    }

    @Override
    public UserDto updateUserDetails(UserDto userDto, String userId) {
        if (userDto == null) {
            logger.warn("USER_008_UPDATE_NULL_DATA: Attempted user update with null user data");
            throw new IllegalArgumentException("Please provide valid data.");
        }
        if (userId == null || userId.isEmpty()) {
            logger.warn("USER_009_UPDATE_INVALID_USER_ID: Attempted user update with invalid user ID");
            throw new IllegalArgumentException("Please provide valid userId");
        }
        
        logger.info("USER_010_UPDATE_USER_START: Starting user update for userId: {}", userId);
        
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepo.findById(uId).orElseThrow(() -> {
            logger.warn("USER_011_UPDATE_USER_NOT_FOUND: User not found for update - userId: {}", userId);
            return new ResourceNotFoundException("User not found for provided user Id.");
        });
        
        if (userDto.getName() != null) {
            user.setName(userDto.getName());
            logger.debug("USER_012_UPDATE_NAME_FIELD: User name field updated");
        }
        if (userDto.getImage() != null) {
            user.setImage(userDto.getImage());
            logger.debug("USER_013_UPDATE_IMAGE_FIELD: User image field updated");
        }
        if (userDto.getProvider() != null) {
            user.setProvider(userDto.getProvider());
            logger.debug("USER_014_UPDATE_PROVIDER_FIELD: User provider field updated to: {}", userDto.getProvider());
        }
        if (userDto.getPassword() != null) {
            user.setPassword(userDto.getPassword());
            logger.debug("USER_015_UPDATE_PASSWORD_FIELD: User password field updated");
        }
        if (userDto.getEnable() != null) {
            user.setEnable(userDto.getEnable());
            logger.debug("USER_016_UPDATE_ENABLE_FIELD: User enable status updated to: {}", userDto.getEnable());
        }

        User newUser = userRepo.save(user);
        
        logger.info("USER_017_UPDATE_USER_SUCCESS: User update completed successfully - userId: {}", newUser.getId());
        return mapper.map(newUser, UserDto.class);
    }

    @Override
    public String deleteUser(String userId) {
        if (userId == null || userId.isEmpty()) {
            logger.warn("USER_018_DELETE_INVALID_USER_ID: Attempted user deletion with invalid user ID");
            throw new IllegalArgumentException("Please provide valid userId");
        }
        
        logger.info("USER_019_DELETE_USER_START: Starting user deletion for userId: {}", userId);
        
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepo.findById(uId).orElseThrow(() -> {
            logger.warn("USER_020_DELETE_USER_NOT_FOUND: User not found for deletion - userId: {}", userId);
            return new ResourceNotFoundException("User not found for provided user Id.");
        });
        
        userRepo.delete(user);
        
        logger.info("USER_021_DELETE_USER_SUCCESS: User deleted successfully - userId: {}", userId);
        return "User deleted successfully for given user Id.";
    }

    @Override
    public UserDto getUserById(String userId) {
        if (userId == null || userId.isEmpty()) {
            logger.warn("USER_022_GET_BY_ID_INVALID_USER_ID: Attempted user retrieval with invalid user ID");
            throw new IllegalArgumentException("Please provide valid userId");
        }
        
        logger.debug("USER_023_GET_USER_BY_ID_START: Fetching user by userId: {}", userId);
        
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepo.findById(uId).orElseThrow(() -> {
            logger.warn("USER_024_GET_BY_ID_USER_NOT_FOUND: User not found - userId: {}", userId);
            return new ResourceNotFoundException("User not found for provided user id");
        });
        
        logger.info("USER_025_GET_USER_BY_ID_SUCCESS: User found successfully - userId: {}", userId);
        return mapper.map(user, UserDto.class);
    }

    @Override
    public Iterable<UserDto> getAllUsers() {
        logger.info("USER_026_GET_ALL_USERS_START: Fetching all users");
        
        var allUsers = userRepo.findAll()
                .stream()
                .map(user -> mapper.map(user, UserDto.class))
                .toList();
        
        logger.info("USER_027_GET_ALL_USERS_SUCCESS: Retrieved all users - total count: {}", allUsers.size());
        return allUsers;
    }
    
    private String maskEmail(String email) {
        if (email == null || email.length() < 3) return "***";
        return email.substring(0, 2) + "***@***";
    }
}
