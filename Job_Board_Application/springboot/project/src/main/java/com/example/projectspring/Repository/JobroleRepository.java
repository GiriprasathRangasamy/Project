// JobRepository.java
package com.example.projectspring.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.projectspring.Model.Jobrole;

import java.util.List;
import java.util.Optional;

@Repository
public interface JobroleRepository extends JpaRepository<Jobrole, Integer> {
    List<Jobrole> findByRoleContainingIgnoreCase(String query);
    Optional<Jobrole> findByRole(String role);
}
