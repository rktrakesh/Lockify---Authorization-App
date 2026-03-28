package authentication_backend.services;

import authentication_backend.dto.UserDto;

public interface UserService {

    UserDto createNewUser (UserDto userDto);

    UserDto getUserByEmail (String email);

    UserDto updateUserDetails (UserDto userDto, String userId);

    String deleteUser (String userId);

    UserDto getUserById (String userId);

    Iterable<UserDto> getAllUsers ();

}
