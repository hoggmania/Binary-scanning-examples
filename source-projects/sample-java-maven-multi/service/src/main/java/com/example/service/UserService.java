package com.example.service;

import com.example.core.model.User;
import com.example.core.util.ValidationUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {
    
    private final List<User> users = new ArrayList<>();
    private Long nextId = 1L;

    public User createUser(String username, String email) {
        if (!ValidationUtil.isValidUsername(username)) {
            throw new IllegalArgumentException("Invalid username");
        }
        if (!ValidationUtil.isValidEmail(email)) {
            throw new IllegalArgumentException("Invalid email");
        }
        
        User user = new User(nextId++, username, email);
        users.add(user);
        return user;
    }

    public Optional<User> findById(Long id) {
        return users.stream()
                .filter(u -> u.getId().equals(id))
                .findFirst();
    }

    public List<User> findAll() {
        return new ArrayList<>(users);
    }
}
