package com.example.projectspring.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.example.projectspring.Model.Review;
import com.example.projectspring.Repository.ReviewRepository;

import java.util.List;

@RestController
@CrossOrigin
@RequestMapping("/reviews")
public class ReviewController {

    @Autowired
    private ReviewRepository reviewRepository;

    @GetMapping("/company/{companyName}")
    public List<Review> getReviewsByCompany(@PathVariable String companyName) {
        return reviewRepository.findByCompanyname(companyName); // Adjust to filter by companyId
    }

    @PostMapping
    public Review addReview(@RequestBody Review review) {
        return reviewRepository.save(review);
    }
}