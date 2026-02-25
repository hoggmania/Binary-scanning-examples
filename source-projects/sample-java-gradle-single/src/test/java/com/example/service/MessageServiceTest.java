package com.example.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MessageServiceTest {
    
    private final MessageService service = new MessageService();
    
    @Test
    void testFormatMessage() {
        String result = service.formatMessage("test message");
        assertEquals("Test message", result);
    }
    
    @Test
    void testFormatEmptyMessage() {
        String result = service.formatMessage("");
        assertEquals("No message", result);
    }
}
