package com.example.web.controller;

import com.example.core.model.Product;
import com.example.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    
    @Autowired
    private ProductService productService;

    @PostMapping
    public ResponseEntity<Product> createProduct(@RequestParam String name, @RequestParam Double price) {
        Product product = productService.createProduct(name, price);
        return ResponseEntity.ok(product);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Product> getProduct(@PathVariable Long id) {
        return productService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/price")
    public ResponseEntity<String> getProductPrice(@PathVariable Long id) {
        String formattedPrice = productService.getFormattedPrice(id);
        return ResponseEntity.ok(formattedPrice);
    }

    @GetMapping
    public List<Product> getAllProducts() {
        return productService.findAll();
    }
}
