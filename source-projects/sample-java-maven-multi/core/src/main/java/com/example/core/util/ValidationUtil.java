package com.example.core.util;

import org.apache.commons.lang3.StringUtils;

public class ValidationUtil {
    
    public static boolean isValidEmail(String email) {
        return StringUtils.isNotBlank(email) && email.contains("@");
    }
    
    public static boolean isValidUsername(String username) {
        return StringUtils.isNotBlank(username) && username.length() >= 3;
    }
}
