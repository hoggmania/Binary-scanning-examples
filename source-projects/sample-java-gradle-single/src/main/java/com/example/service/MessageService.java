package com.example.service;

import org.springframework.stereotype.Service;
import org.apache.commons.lang3.StringUtils;

@Service
public class MessageService {
    
    public String formatMessage(String text) {
        if (StringUtils.isBlank(text)) {
            return "No message";
        }
        return StringUtils.capitalize(text);
    }
}
