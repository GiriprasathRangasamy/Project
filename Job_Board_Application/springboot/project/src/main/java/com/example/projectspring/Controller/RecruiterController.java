package com.example.projectspring.Controller;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.projectspring.Model.Job;
import com.example.projectspring.Model.Jobrole;
import com.example.projectspring.Model.Recruiter;
import com.example.projectspring.Repository.RecruiterRepo;
import com.example.projectspring.Service.JobService;


@RestController
@CrossOrigin
@RequestMapping("/recruiter")
public class RecruiterController {
    
     @Autowired JobService servicejob;
     @Autowired RecruiterRepo repo;
    
    @PostMapping("/postjob")
    public String postjob(@RequestBody Job job)
    {
        return servicejob.postjob(job);
    }
    @GetMapping("/getlistjob/{email}")
    public List<Job> getlistjobemail(@PathVariable String email)
    {
        return servicejob.getbyemail(email);
    }
    @GetMapping("/jobedit/{id}")
    public Optional<Job> getMethodName1(@PathVariable int id) {
        return servicejob.getbyidservice(id);
    }
    @GetMapping("/roles")
    public List<Jobrole> getJobRoles(@RequestParam String query) {
        return servicejob.getJobRoles(query);
    }
    @GetMapping("/logindetails/{email}")
    public Optional<Recruiter> getMethodName(@PathVariable String email) {
        return repo.findById(email);
    }
    @DeleteMapping("deletejob/{jobId}")
    public String deletejob(@PathVariable int jobId)
    {
        return servicejob.deletejob(jobId);
    }
    @GetMapping("/getbycompanyname/{companyName}")
    public List<Job> getbycompanyname(@PathVariable String companyName) {
        return servicejob.getjobbycompany(companyName);
    }
    
}