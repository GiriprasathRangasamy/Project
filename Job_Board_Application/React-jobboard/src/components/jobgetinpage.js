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

const JobListingsPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isVisible, setIsVisible] = useState(false);
  const [reviews, setReviews] = useState([]);
  const [newReview, setNewReview] = useState({
    role: '',
    stars: 0,
    postedBy: '',
    description: '',
  });
  const [filterCity, setFilterCity] = useState('');
  const [filterRole, setFilterRole] = useState('');

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

  useEffect(() => {
    const fetchReviews = async () => {
      try {
        if (job) {
          const response = await fetch(`http://localhost:8080/reviews/company/${job.companyName}`);
          if (!response.ok) {
            throw new Error('Failed to fetch reviews');
          }
          const reviewsData = await response.json();
          setReviews(reviewsData);
        }
      } catch (error) {
        console.error('Error fetching reviews:', error);
      }
    };

    fetchReviews();
  }, [job]);

  const handleCheckKnowledge = () => {
    setIsVisible(true);
  };

  const handleReviewChange = (e) => {
    const { name, value } = e.target;
    setNewReview((prev) => ({ ...prev, [name]: value }));
  };

  const handleReviewSubmit = async () => {
    console.log("review submitted");
    try {
      const response = await fetch('http://localhost:8080/reviews', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ...newReview, companyname: job.companyName, city: job.city }),
      });
      if (!response.ok) {
        throw new Error('Failed to submit review');
      }
      const reviewData = await response.json();
      setReviews((prev) => [...prev, reviewData]);
      setNewReview({
        role: '',
        stars: 0,
        postedBy: '',
        description: ''
      });
    } catch (error) {
      console.error('Error submitting review:', error);
    }
  };

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
                      variant="outlined"
                      onClick={handleCheckKnowledge}
                      sx={{ mt: 2, fontSize: '1.1rem', padding: '10px 20px' }}
                      href={`/Mcq/${id}`}
                      target="_blank"
                    >
                      Check Required Knowledge
                    </Button>
                    <Button
                      href={job.applyLink}
                      target="_blank"
                      rel="noopener noreferrer"
                      variant="contained"
                      color="primary"
                      sx={{ mt: 2, ml: 2, fontSize: '1.1rem', padding: '10px 20px' }}
                    >
                      Apply Now
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>

            {/* Reviews Section */}
            <Container sx={{ marginTop: '40px' }}>
              <Typography variant="h4" gutterBottom>
                Reviews
              </Typography>
              <Card style={{marginBottom:"10px",padding:"20px"}}>
              <TextField
                label="Filter by City"
                value={filterCity}
                onChange={(e) => setFilterCity(e.target.value)}
                fullWidth
                sx={{ mb: 2 }}
              />
              <TextField
                label="Filter by Role"
                value={filterRole}
                onChange={(e) => setFilterRole(e.target.value)}
                fullWidth
                sx={{ mb: 2 }}
              />
              </Card>
              {reviews
                .filter((review) =>
                  (filterCity === '' || review.city.toLowerCase().includes(filterCity.toLowerCase())) &&
                  (filterRole === '' || review.role.toLowerCase().includes(filterRole.toLowerCase()))
                )
                .map((review) => (
                  <Card key={review.id} sx={{ mb: 2, p: 2 }} style={{gap:"10px"}}>
                    <Typography variant="h6" component="h3">
                      {review.role}
                    </Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                    <strong>City:</strong>{review.city}
                    </Typography>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Rating value={review.stars} readOnly />
                      <Typography variant="body2">({review.stars})</Typography>
                    </Stack>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      <strong>Posted by:</strong> {review.postedBy}
                    </Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                   <p> <strong>Description:</strong></p>{review.description}
                    </Typography>
                  </Card>
                ))}
              {reviews.length === 0 && (
                <Typography variant="body1">No reviews yet.</Typography>
              )}
              <Card sx={{ mt: 4, p: 2 }}>
                <Typography variant="h6" component="h3" gutterBottom>
                  Add a Review
                </Typography>
                <TextField
                  label="Role"
                  name="role"
                  value={newReview.role}
                  onChange={handleReviewChange}
                  fullWidth
                  sx={{ mb: 2 }}
                />
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography variant="body1">Rating:</Typography>
                  <Rating
                    name="stars"
                    value={newReview.stars}
                    onChange={(e, newValue) => setNewReview((prev) => ({ ...prev, stars: newValue }))}
                  />
                </Stack>
                <TextField
                  label="Posted By"
                  name="postedBy"
                  value={newReview.postedBy}
                  onChange={handleReviewChange}
                  fullWidth
                  sx={{ mb: 2 }}
                />
                <TextField
                  label="Description"
                  name="description"
                  value={newReview.description}
                  onChange={handleReviewChange}
                  fullWidth
                  multiline
                  rows={4}
                  sx={{ mb: 2 }}
                />
                <Button
                  variant="contained"
                  color="primary"
                  onClick={handleReviewSubmit}
                >
                  Submit Review
                </Button>
              </Card>
            </Container>
          </>
        )}
      </Container>
      <UserFooter />
    </>
  );
};

export default JobListingsPage;
