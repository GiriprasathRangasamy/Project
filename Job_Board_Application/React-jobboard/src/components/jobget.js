import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  TextField,
  Button,
  Typography,
  Container,
  Box,
  Grid,
  MenuItem,
  Select,
  InputLabel,
  FormControl,
  Pagination,
  Paper,
  IconButton,
  Tooltip,
  Chip,
} from '@mui/material';
import LocationOnIcon from '@mui/icons-material/LocationOn';
import CalendarTodayIcon from '@mui/icons-material/CalendarToday';
import WorkOutlineIcon from '@mui/icons-material/WorkOutline';
import MonetizationOnIcon from '@mui/icons-material/MonetizationOn';
import BusinessCenterIcon from '@mui/icons-material/BusinessCenter';
import RefreshIcon from '@mui/icons-material/Refresh';
import UserNavbar from './usernavbar';
import UserFooter from './userfooter';

const JobGetPage = () => {
  const [filteredJobs, setFilteredJobs] = useState([]); // Holds the filtered jobs
  const [searchTermRole, setSearchTermRole] = useState(''); // Holds the role search term
  const [searchTermLocation, setSearchTermLocation] = useState(''); // Holds the location search term
  const [jobType, setJobType] = useState(''); // Holds the job type
  const [salaryRange, setSalaryRange] = useState({ min: '', max: '' }); // Holds the salary range as an object
  const [experience, setExperience] = useState(''); // Holds the experience level
  const [page, setPage] = useState(1); // Holds the current page number
  const jobsPerPage = 5; // Number of jobs to display per page

  const fetchJobs = useCallback(async () => {
    const url = new URL('http://localhost:8080/user/jobs');
    url.searchParams.append('role', searchTermRole);
    url.searchParams.append('city', searchTermLocation);
    url.searchParams.append('jobType', jobType);
    url.searchParams.append('experience', experience);
    url.searchParams.append('salaryMin', salaryRange.min || 0);
    url.searchParams.append('salaryMax', salaryRange.max || 10000000000000000000);

    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    const data = await response.json();
    console.log(data);
    setFilteredJobs(Array.isArray(data) ? data : []);
  }, [searchTermRole, searchTermLocation, jobType, experience, salaryRange]);

  useEffect(() => {
    fetchJobs();
  }, [fetchJobs]);

  const handleSearchByRoleChange = (e) => {
    setSearchTermRole(e.target.value);
  };

  const handleSearchLocationChange = (e) => {
    setSearchTermLocation(e.target.value);
  };

  const handleJobTypeChange = (e) => {
    setJobType(e.target.value);
  };

  const handleExperienceChange = (e) => {
    setExperience(e.target.value);
  };

  const handleSalaryRangeChange = (field) => (e) => {
    setSalaryRange((prev) => ({
      ...prev,
      [field]: e.target.value,
    }));
  };

  const handlePageChange = (event, value) => {
    setPage(value);
  };

  const resetFilters = () => {
    setSearchTermRole('');
    setSearchTermLocation('');
    setJobType('');
    setExperience('');
    setSalaryRange({ min: '', max: '' });
  };

  const displayedJobs = filteredJobs.slice(
    (page - 1) * jobsPerPage,
    page * jobsPerPage
  );

  return (
    <div>
      <UserNavbar />
      <Container sx={{ marginTop: '40px', marginBottom: '40px' }}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Paper
              sx={{
                padding: '3vw',
                position: 'sticky',
                borderRadius: '10px',
                boxShadow: '0px 4px 10px rgba(0, 0, 0, 0.1)',
                backgroundColor: '#f5f5f5',
                border: 'solid 1px #aaabad',
              }}
            >
              <Typography variant="h6" align="center" gutterBottom>
                Filter Jobs
              </Typography>
              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Typography variant="subtitle1">Filters</Typography>
                <Tooltip title="Reset Filters" arrow>
                  <IconButton onClick={resetFilters}>
                    <RefreshIcon sx={{ color: '#004d40' }} />
                  </IconButton>
                </Tooltip>
              </Box>
              <TextField
                label="Search by Role"
                variant="outlined"
                fullWidth
                value={searchTermRole}
                onChange={handleSearchByRoleChange}
                sx={{
                  marginTop: '16px',
                  borderRadius: '5px',
                  '& .MuiOutlinedInput-root': {
                    '& fieldset': {
                      borderColor: '#00796b',
                    },
                    '&:hover fieldset': {
                      borderColor: '#004d40',
                    },
                    '&.Mui-focused fieldset': {
                      borderColor: '#004d40',
                    },
                  },
                }}
              />
              <TextField
                label="Search by Location"
                variant="outlined"
                fullWidth
                value={searchTermLocation}
                onChange={handleSearchLocationChange}
                sx={{
                  marginTop: '16px',
                  borderRadius: '5px',
                  '& .MuiOutlinedInput-root': {
                    '& fieldset': {
                      borderColor: '#00796b',
                    },
                    '&:hover fieldset': {
                      borderColor: '#004d40',
                    },
                    '&.Mui-focused fieldset': {
                      borderColor: '#004d40',
                    },
                  },
                }}
              />
              <FormControl
                variant="outlined"
                fullWidth
                sx={{
                  marginTop: '16px',
                  borderRadius: '5px',
                }}
              >
                <InputLabel id="jobType-label">Job Type</InputLabel>
                <Select
                  labelId="jobType-label"
                  value={jobType}
                  onChange={handleJobTypeChange}
                  label="Job Type"
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="Full Time">Full-time</MenuItem>
                  <MenuItem value="Part Time">Part-time</MenuItem>
                  <MenuItem value="Internship">Internship</MenuItem>
                </Select>
              </FormControl>
              <FormControl
                variant="outlined"
                fullWidth
                sx={{
                  marginTop: '16px',
                  borderRadius: '5px',
                }}
              >
                <InputLabel id="experience-label">Experience</InputLabel>
                <Select
                  labelId="experience-label"
                  value={experience}
                  onChange={handleExperienceChange}
                  label="Experience"
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="0-1">0-1 years</MenuItem>
                  <MenuItem value="1-3">1-3 years</MenuItem>
                  <MenuItem value="3-5">3-5 years</MenuItem>
                  <MenuItem value="5+">5+ years</MenuItem>
                </Select>
              </FormControl>
              <Box display="flex" justifyContent="space-between" alignItems="center" mt={2}>
                <Typography gutterBottom>Salary Range</Typography>
              </Box>
              <Box display="flex" gap={2} mt={1} mb={3}>
                <TextField
                  label="Min Salary"
                  variant="outlined"
                  fullWidth
                  value={salaryRange.min}
                  onChange={handleSalaryRangeChange('min')}
                  sx={{
                    borderRadius: '5px',
                    '& .MuiOutlinedInput-root': {
                      '& fieldset': {
                        borderColor: '#00796b',
                      },
                      '&:hover fieldset': {
                        borderColor: '#004d40',
                      },
                      '&.Mui-focused fieldset': {
                        borderColor: '#004d40',
                      },
                    },
                  }}
                />
                <TextField
                  label="Max Salary"
                  variant="outlined"
                  fullWidth
                  value={salaryRange.max}
                  onChange={handleSalaryRangeChange('max')}
                  sx={{
                    borderRadius: '5px',
                    '& .MuiOutlinedInput-root': {
                      '& fieldset': {
                        borderColor: '#00796b',
                      },
                      '&:hover fieldset': {
                        borderColor: '#004d40',
                      },
                      '&.Mui-focused fieldset': {
                        borderColor: '#004d40',
                      },
                    },
                  }}
                />
              </Box>
              <Box mt={2} display="flex" justifyContent="center">
                <Button
                  variant="contained"
                  onClick={fetchJobs}
                  sx={{
                    backgroundColor: '#004d40',
                    color: 'white',
                    padding: '10px 20px',
                    borderRadius: '5px',
                    '&:hover': {
                      backgroundColor: '#00796b',
                    },
                  }}
                >
                  Apply Filters
                </Button>
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={8}>
            {displayedJobs.length > 0 ? (
              displayedJobs.map((job) => (
                <Link to={`/usergetlist/${job.id}`} style={{ textDecoration: 'none' }}>
                  <Paper
                    key={job.id}
                    sx={{
                      padding: '20px',
                      marginBottom: '20px',
                      borderRadius: '10px',
                      boxShadow: '0px 4px 10px rgba(0, 0, 0, 0.1)',
                      '&:hover': {
                        boxShadow: '0px 6px 15px rgba(0, 0, 0, 0.2)',
                      },
                      border: 'solid 0.5px #aaabad',
                    }}
                  >
                    <Typography variant="h4" component="h2" gutterBottom>
                      {job.companyName}
                    </Typography>
                    <Typography
                      variant="h6"
                      component="h2"
                      gutterBottom
                      style={{ color: '#828487' }}
                    >
                      {job.role}
                    </Typography>

                    <Box display="flex" flexWrap="wrap" gap={1} mb={2}>
                      <Chip
                        icon={<LocationOnIcon />}
                        label={job.city}
                        color="secondary"
                        variant="outlined"
                      />
                      <Chip
                        icon={<CalendarTodayIcon />}
                        label={`Posted on: ${job.startDate}`}
                        variant="outlined"
                        sx={{ borderColor: '#00796b' }}
                      />
                      <Chip
                        icon={<CalendarTodayIcon />}
                        label={`Apply By: ${job.applyBy}`}
                        variant="outlined"
                        sx={{ borderColor: '#00796b' }}
                      />
                      <Chip
                        icon={<WorkOutlineIcon />}
                        label={job.jobType}
                        variant="outlined"
                        sx={{ borderColor: '#004d40' }}
                      />
                      <Chip
                        icon={<MonetizationOnIcon />}
                        label={`above Rs.${job.salary}`}
                        variant="outlined"
                        sx={{ borderColor: '#ff8a65' }}
                        style={{ fontWeight: 'bold' }}
                      />
                    </Box>
                  </Paper>
                </Link>
              ))
            ) : (
              <Typography variant="h6" align="center" color="textSecondary">
                No jobs found. Please try different filters.
              </Typography>
            )}
            {filteredJobs.length > jobsPerPage && (
              <Box mt={3} display="flex" justifyContent="center">
                <Pagination
                  count={Math.ceil(filteredJobs.length / jobsPerPage)}
                  page={page}
                  onChange={handlePageChange}
                  color="primary"
                  sx={{
                    '& .MuiPaginationItem-root': {
                      color: '#004d40',
                      '&:hover': {
                        backgroundColor: '#00796b',
                        color: 'white',
                      },
                    },
                    '& .Mui-selected': {
                      backgroundColor: '#004d40 !important',
                      color: 'white',
                    },
                  }}
                />
              </Box>
            )}
          </Grid>
        </Grid>
      </Container>
      <UserFooter />
    </div>
  );
};

export default JobGetPage;
