package com.example.projectspring.Service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.projectspring.Model.Job;
import com.example.projectspring.Model.Jobrole;
import com.example.projectspring.Repository.JobRepository;
import com.example.projectspring.Repository.JobroleRepository;

@Service
public class JobService {

    @Autowired
    private JobRepository repo;

    @Autowired
    private JobroleRepository repojob;

    public String postjob(Job job) {
        // Check if the role exists in Jobrole repository
        String role = job.getRole();
        Optional<Jobrole> existingRole = repojob.findByRole(role);
        
        if (!existingRole.isPresent()) {
            // If the role does not exist, save it in the Jobrole repository
            Jobrole newRole = new Jobrole();
            newRole.setRole(role);
            repojob.save(newRole);
        }
        
        // Save the job in the Job repository
        repo.save(job);
        return "Successful";
    }

    public Optional<Job> getjob(int id) {
        return repo.findById(id);
    }

    public List<Job> getbyemail(String email) {
        return repo.findByEmail(email);
    }

    public Optional<Job> getbyidservice(int id) {
        return repo.findById(id);
    }

    public List<Job> alljobs() {
        return repo.findAll();
    }

    public List<Job> getFilteredJobs(String role, String city, String jobType, String experience, Double salaryMin, Double salaryMax) {
        if (jobType.equals("All"))
            jobType = "";

        if (experience.equals("All"))
            experience = "";

        List<Job> giri = repo.findJobs(role, city, jobType, experience, salaryMin, salaryMax);
        System.out.println(giri);
        return giri;
    }

    public List<Jobrole> getJobRoles(@RequestParam String query) {
        return repojob.findByRoleContainingIgnoreCase(query);
    }
    public String deletejob(int id)
    {
        Job j=repo.findById(id).orElse(null);
        if(j!=null)
        {
            repo.deleteById(id);
            return "Successfully Deleted";
        }
        else
        return "Job not exist";
    }
    public List<Job> getjobbycompany(String companyname)
    {
        return repo.findByCompanyName(companyname);
    }
}
