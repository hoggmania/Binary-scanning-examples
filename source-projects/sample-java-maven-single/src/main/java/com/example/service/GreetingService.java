package com.example.service;

import org.springframework.stereotype.Service;
import org.apache.commons.lang3.StringUtils;

@Service
public class GreetingService {
    
    public String greet(String name) {
        if (StringUtils.isBlank(name)) {
            return "Hello, World!";
        }
        return "Hello, " + StringUtils.capitalize(name) + "!";
    }
}
