package com.example.projectspring.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.projectspring.Model.Recruiter;

@Repository
public interface RecruiterRepo extends JpaRepository<Recruiter, String> {
}
