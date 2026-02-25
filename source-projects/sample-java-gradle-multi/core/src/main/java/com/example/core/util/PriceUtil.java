package com.example.core.util;

import org.apache.commons.lang3.StringUtils;

public class PriceUtil {
    
    public static String formatPrice(Double price) {
        if (price == null) {
            return "$0.00";
        }
        return String.format("$%.2f", price);
    }
    
    public static boolean isValidProductName(String name) {
        return StringUtils.isNotBlank(name) && name.length() >= 2;
    }
}
