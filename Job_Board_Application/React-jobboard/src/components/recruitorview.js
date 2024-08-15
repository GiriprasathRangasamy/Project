import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Grid,
  Chip,
  Container,
  CircularProgress,
  TextField,
  Rating,
  Stack,
} from '@mui/material';
import UserNavbar from './usernavbar';
import UserFooter from './userfooter';
import { useRecemail } from '../context/recruiterauth';
import { useNavigate, useParams } from 'react-router-dom';

const Recruitorview= () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { recemail } = useRecemail();

  useEffect(() => {
    const fetchJobData = async () => {
      try {
        const response = await fetch(`http://localhost:8080/user/jobdetail/${id}`);
        if (!response.ok) {
          throw new Error('Failed to fetch job data');
        }
        const jobData = await response.json();
        setJob(jobData);
        setLoading(false);
      } catch (error) {
        console.error('Error fetching job:', error);
        setError('Error fetching job details. Please try again later.');
        setLoading(false);
      }
    };

    fetchJobData();
  }, [id]);
 
 

  if (loading) {
    return (
      <Container sx={{ textAlign: 'center', marginTop: '100px' }}>
        <CircularProgress />
      </Container>
    );
  }

  if (error) {
    return (
      <Container sx={{ textAlign: 'center', marginTop: '100px' }}>
        <Typography variant="h5" color="error">
          {error}
        </Typography>
      </Container>
    );
  }

  return (
    <>
      <UserNavbar />
      <Container maxWidth="lg" sx={{ paddingTop: '20px', marginBottom: '30px' }}>
        {job && (
          <>
            <Typography variant="h3" component="h1" gutterBottom align="center">
              {job.companyName}
            </Typography>
            <Grid container justifyContent="center" spacing={4}>
              <Grid item xs={12} md={8} lg={8}>
                <Card
                  sx={{
                    width: '80vw',
                    maxWidth: '100%',
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    boxShadow: 3,
                  }}
                >
                  <CardContent sx={{ padding: '24px' }}>
                    <Typography
                      variant="h4"
                      component="h2"
                      gutterBottom
                      sx={{ fontWeight: 'bold', fontSize: '1.8rem' }}
                    >
                      {job.role}
                    </Typography>
                    <Typography
                      variant="body1"
                      color="text.secondary"
                      sx={{ fontSize: '1.2rem' }}
                    >
                      Location: {job.city}, {job.address}
                    </Typography>
                    <Typography
                      variant="body1"
                      color="text.secondary"
                      sx={{ fontSize: '1.2rem' }}
                    >
                      Start Date: {new Date(job.startDate).toLocaleDateString()}
                    </Typography>
                    <Typography
                      variant="body1"
                      color="text.secondary"
                      sx={{ fontSize: '1.2rem' }}
                    >
                      Apply By: {new Date(job.applyBy).toLocaleDateString()}
                    </Typography>
                    <Typography
                      variant="body1"
                      color="text.secondary"
                      sx={{ fontSize: '1.2rem' }}
                    >
                      Salary: Rs.{job.salary}
                    </Typography>
                    <Typography
                      variant="body1"
                      color="text.secondary"
                      sx={{ fontSize: '1.2rem' }}
                    >
                      Experience Required: {job.experience} years
                    </Typography>
                    <Typography
                      variant="body1"
                      color="text.secondary"
                      gutterBottom
                      sx={{ fontSize: '1.2rem' }}
                    >
                      Job Type: {job.jobType}
                    </Typography>
                    <Typography
                      variant="body1"
                      gutterBottom
                      sx={{ fontSize: '1.2rem', fontWeight: 'bold' }}
                    >
                      Skills:
                    </Typography>
                    <Box sx={{ mb: 2 }}>
                      {job.skills.map((skill, skillIndex) => (
                        <Chip
                          key={skillIndex}
                          label={skill}
                          sx={{
                            mr: 1,
                            mb: 1,
                            fontSize: '1.1rem',
                            padding: '0 10px',
                            height: '28px',
                          }}
                        />
                      ))}
                    </Box>
                    <Typography
                      variant="body1"
                      gutterBottom
                      sx={{ fontSize: '1.2rem', fontWeight: 'bold' }}
                    >
                      Eligibility Criteria:
                    </Typography>
                    <Box sx={{ mb: 2 }}>
                      {job.eligibility.map((criteria, criteriaIndex) => (
                        <Chip
                          key={criteriaIndex}
                          label={criteria}
                          sx={{
                            mr: 1,
                            mb: 1,
                            fontSize: '1.1rem',
                            padding: '0 10px',
                            height: '28px',
                          }}
                        />
                      ))}
                    </Box>
                    <Typography
                      variant="body1"
                      gutterBottom
                      sx={{ fontSize: '1.2rem', fontWeight: 'bold' }}
                    >
                      About the Job:
                    </Typography>
                    <Typography
                      variant="body1"
                      color="text.secondary"
                      sx={{ mb: 2, fontSize: '1.2rem' }}
                    >
                      {job.aboutJob}
                    </Typography>
                    <Typography
                      variant="body1"
                      gutterBottom
                      sx={{ fontSize: '1.2rem', fontWeight: 'bold' }}
                    >
                      About the Company:
                    </Typography>
                    <Typography
                      variant="body1"
                      color="text.secondary"
                      sx={{ mb: 2, fontSize: '1.2rem' }}
                    >
                      {job.aboutCompany}
                    </Typography>

                  
                    <Button
                      href="/adminpostlist"
                      
                      rel="noopener noreferrer"
                      variant="contained"
                      color="primary"
                      sx={{ mt: 2, ml: 2, fontSize: '1.1rem', padding: '10px 20px' }}
                    >
                      Go Back
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>

           
          </>
        )}
      </Container>
      <UserFooter />
    </>
  );
};

export default Recruitorview;
