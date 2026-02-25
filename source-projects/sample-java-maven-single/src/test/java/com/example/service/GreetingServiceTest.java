package com.example.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GreetingServiceTest {
    
    private final GreetingService service = new GreetingService();
    
    @Test
    void testGreetWithName() {
        String result = service.greet("john");
        assertEquals("Hello, John!", result);
    }
    
    @Test
    void testGreetWithoutName() {
        String result = service.greet("");
        assertEquals("Hello, World!", result);
    }
}
