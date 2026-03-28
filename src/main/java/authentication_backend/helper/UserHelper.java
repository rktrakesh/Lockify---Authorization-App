package authentication_backend.helper;

import java.util.UUID;

public class UserHelper {

    public static UUID parseUUID (String uId) {
        try {
            return UUID.fromString(uId);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

}
