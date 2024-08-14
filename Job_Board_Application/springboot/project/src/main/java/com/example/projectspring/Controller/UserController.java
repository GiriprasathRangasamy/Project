package com.example.projectspring.Controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;

import com.example.projectspring.Model.Job;
import com.example.projectspring.Service.JobService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;



@RestController
@CrossOrigin
@RequestMapping("/user")
public class UserController {
    
    @Autowired JobService servicejob;
    
    @GetMapping("/jobs")
    public List<Job> getFilteredJobs(
        @RequestParam(value = "role", required = false) String role,
        @RequestParam(value = "city", required = false) String city,
        @RequestParam(value = "jobType", required = false) String jobType,
        @RequestParam(value = "experience", required = false) String experience,
        @RequestParam(value = "salaryMin", required = false) String salaryMin,
        @RequestParam(value = "salaryMax", required = false) String salaryMax
    ) {
        Double minSalary = salaryMin != null ? Double.valueOf(salaryMin) : null;
        Double maxSalary = salaryMax != null ? Double.valueOf(salaryMax) : null;
        System.out.print("hi i there");
        return servicejob.getFilteredJobs(role, city, jobType, experience, minSalary, maxSalary);
    }
     @GetMapping("/jobdetail/{id}")
    public Optional<Job> getMethodName1(@PathVariable int id) {
        return servicejob.getbyidservice(id);
    }
    @GetMapping("/alljob")
    public List<Job> getalljob()
    {
        return servicejob.alljobs();
    }
}
