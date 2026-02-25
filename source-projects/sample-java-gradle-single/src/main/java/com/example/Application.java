package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.apache.commons.lang3.StringUtils;
import com.google.gson.Gson;

@SpringBootApplication
public class Application {
    
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
        
        // Demo usage of dependencies
        String message = StringUtils.capitalize("hello gradle world");
        Gson gson = new Gson();
        String json = gson.toJson(new Message(message));
        
        System.out.println("Gradle Application started: " + json);
    }
    
    static class Message {
        private String text;
        
        public Message(String text) {
            this.text = text;
        }
        
        public String getText() {
            return text;
        }
    }
}
