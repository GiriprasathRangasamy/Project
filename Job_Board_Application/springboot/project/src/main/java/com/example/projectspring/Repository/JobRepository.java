package com.example.projectspring.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.projectspring.Model.Job;
import java.util.List;

@Repository
public interface JobRepository extends JpaRepository<Job, Integer> {

    List<Job> findByEmail(String email);
    List<Job> findByCompanyName(String companyName);

    @Query(value = "SELECT * FROM job j WHERE "
    + "(:role IS NULL OR j.role LIKE CONCAT('%', :role, '%')) "
    + "AND (:city IS NULL OR j.city LIKE CONCAT('%', :city, '%')) "
    + "AND (:job_type IS NULL OR j.job_type LIKE CONCAT('%', :job_type, '%')) "
   + "AND (:experience IS NULL OR j.experience LIKE CONCAT('%', :experience, '%')) "
    + "AND (:salaryMin IS NULL OR j.salary >= :salaryMin) "
    + "AND (:salaryMax IS NULL OR j.salary <= :salaryMax)", nativeQuery = true)
List<Job> findJobs(
        @Param("role") String role,
        @Param("city") String city,
       @Param("job_type") String job_type,
       @Param("experience") String experience,
        @Param("salaryMin") Double salaryMin,
        @Param("salaryMax") Double salaryMax
);
}
