package com.example.service;

import com.example.core.model.Product;
import com.example.core.util.PriceUtil;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class ProductService {
    
    private final List<Product> products = new ArrayList<>();
    private Long nextId = 1L;

    public Product createProduct(String name, Double price) {
        if (!PriceUtil.isValidProductName(name)) {
            throw new IllegalArgumentException("Invalid product name");
        }
        if (price == null || price < 0) {
            throw new IllegalArgumentException("Invalid price");
        }
        
        Product product = new Product(nextId++, name, price);
        products.add(product);
        return product;
    }

    public Optional<Product> findById(Long id) {
        return products.stream()
                .filter(p -> p.getId().equals(id))
                .findFirst();
    }

    public List<Product> findAll() {
        return new ArrayList<>(products);
    }
    
    public String getFormattedPrice(Long id) {
        return findById(id)
                .map(p -> PriceUtil.formatPrice(p.getPrice()))
                .orElse("Product not found");
    }
}
