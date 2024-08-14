package com.example.projectspring.Repository;


import org.springframework.data.jpa.repository.JpaRepository;

import com.example.projectspring.Model.Review;
import java.util.List;


public interface ReviewRepository extends JpaRepository<Review, Long> {
    List<Review> findByCompanyname(String companyname);
}
