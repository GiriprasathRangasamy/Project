import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Grid,
  Container,
  CardActionArea,
  CardActions,
  IconButton,
  Stack
} from '@mui/material';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import AdminNavbar from './adminnavbar';
import { Link } from 'react-router-dom';
import AdminFooter from './adminfooter';
import { useRecemail } from '../context/recruiterauth';

const JobList = () => {
  const { recemail } = useRecemail();
  const [jobData, setJobData] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchJobs = async () => {
      try {
        const url = `http://localhost:8080/recruiter/getlistjob/${recemail}`;
        const response = await fetch(url, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });

        if (!response.ok) {
          throw new Error('Failed to fetch job data');
        }

        const data = await response.json();
        setJobData(data);
      } catch (error) {
        console.error('Error fetching jobs:', error);
        setError('Error fetching jobs. Please try again later.');
      }
    };

    fetchJobs();
  }, [recemail]);

  const handleDelete = async (jobId) => {
    const confirmDelete = window.confirm('Are you sure you want to delete this job?');
    if (!confirmDelete) return;

    try {
      const url = `http://localhost:8080/recruiter/deletejob/${jobId}`;
      const response = await fetch(url, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.ok) {
        const message = await response.text();
        alert(message);

        // Remove the deleted job from the state
        setJobData(prevData => prevData.filter(job => job.id !== jobId));
      }
    } catch (error) {
      console.error('Error deleting job:', error);
      setError('Error deleting job. Please try again later.');
    }
  };

  return (
    <>
      <AdminNavbar />
      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        <Typography variant="h3" component="h1" gutterBottom align="center">
          Job Listings
        </Typography>
        {error && (
          <Typography variant="body1" color="error" align="center" gutterBottom>
            {error}
          </Typography>
        )}
        <Grid container spacing={4}>
          {jobData.map((job) => {
            const { id, role, startDate, applyBy } = job;
            return (
              <Grid item xs={12} md={6} lg={4} key={id}>
                <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column'}}>
                  <CardContent>
                    <Typography variant="h5" component="h2" gutterBottom>
                      {role}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Start Date: {new Date(startDate).toLocaleDateString()}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Apply By: {new Date(applyBy).toLocaleDateString()}
                    </Typography>
                    <div style={{display:"flex",flexDirection:"column", alignItems:"center"}}>
                      <div>
                    <Button
                      variant="outlined"
                      href={`/recview/${id}`}
                      sx={{ mt: 2 }}
                      style={{marginRight:"20px"}}
                    >
                      View Details
                    </Button>
                    <Button
                      variant="outlined"
                      href={`/adminpostedit/${id}`}
                      sx={{ mt: 2 }}
                    >
                      Edit Details
                    </Button>
                    </div>
                    <div>
                    <Button
                      variant="contained"
                      color="error"
                      onClick={() => handleDelete(id)}
                      sx={{ mt: 2 }}
                      style={{marginLeft:"20px"}}
                    >
                      Delete
                    </Button>
                    </div>
                    </div>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
          <Grid item xs={12} md={6} lg={4}>
            <Link to='/adminaddpost' style={{ textDecoration: "none" }}>
              <Card
                sx={{
                  height: '31vh',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'center',
                  alignItems: 'center',
                  border: '2px dashed grey',
                }}
              >
                <CardContent sx={{ textAlign: 'center'}}>
                  <AddCircleOutlineIcon sx={{ fontSize: 60, color: 'grey.500', mb: 2 }} />
                  <Typography variant="h6" component="div" color="text.secondary">
                    Add New Job Post
                  </Typography>
                </CardContent>
              </Card>
            </Link>
          </Grid>
        </Grid>
      </Container>
      <AdminFooter />
    </>
  );
};

export default JobList;
