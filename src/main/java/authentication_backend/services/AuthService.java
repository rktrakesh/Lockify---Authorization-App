package authentication_backend.services;

import authentication_backend.dto.UserDto;

public interface AuthService {
    public UserDto resister(UserDto userDto);
}
