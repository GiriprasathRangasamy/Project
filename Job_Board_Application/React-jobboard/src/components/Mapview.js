import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { useNavigate } from 'react-router-dom';
import { FaSearch } from 'react-icons/fa';
import {
  Container,
  Grid,
  Paper,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  IconButton,
  Tooltip,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import UserNavbar from './usernavbar';
import UserFooter from './userfooter';
import './MapView.css';

// Fix the default icon issue with Leaflet
delete L.Icon.Default.prototype._getIconUrl;

L.Icon.Default.mergeOptions({
  iconRetinaUrl:
    'https://unpkg.com/leaflet@1.7.1/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-shadow.png',
});

// Geocoding function using Nominatim
const geocodeAddress = async (address) => {
  try {
    const response = await axios.get(
      `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(
        address
      )}`
    );
    if (response.data && response.data.length > 0) {
      const { lat, lon } = response.data[0];
      return { lat: parseFloat(lat), lon: parseFloat(lon) };
    }
  } catch (error) {
    console.error('Geocoding error:', error);
  }
  // Return default coordinates if geocoding fails
  return { lat: 37.7749, lon: -122.4194 }; // San Francisco coordinates as fallback
};

const MapView = () => {
  const navigate = useNavigate();
  const [jobs, setJobs] = useState([]);
  const [filteredJobs, setFilteredJobs] = useState([]);
  const [location, setLocation] = useState('');
  const [role, setRole] = useState('');
  const [jobType, setJobType] = useState('');
  const [minSalary, setMinSalary] = useState('');
  const [maxSalary, setMaxSalary] = useState('');

  const [mapCenter, setMapCenter] = useState([11.1106, 78.0853]);
  const [mapZoom, setMapZoom] = useState(7);

  useEffect(() => {
    const fetchJobs = async () => {
      try {
        const response = await axios.get('http://localhost:8080/user/alljob');
        const jobData = response.data;

        const jobsWithCoordinates = await Promise.all(
          jobData.map(async (job) => {
            const { lat, lon } = await geocodeAddress(job.address);
            return {
              ...job,
              latitude: lat,
              longitude: lon,
            };
          })
        );

        setJobs(jobsWithCoordinates);
        setFilteredJobs(jobsWithCoordinates);
      } catch (error) {
        console.error('Error fetching jobs:', error);
      }
    };

    fetchJobs();
  }, []);

  const filterJobs = useCallback(() => {
    let newFilteredJobs = [...jobs];

    // Removed location filtering
    // if (location) {
    //   newFilteredJobs = newFilteredJobs.filter((job) =>
    //     job.city.toLowerCase().includes(location.toLowerCase())
    //   );
    // }

    if (role) {
      newFilteredJobs = newFilteredJobs.filter((job) =>
        job.role.toLowerCase().includes(role.toLowerCase())
      );
    }
    if (jobType) {
      newFilteredJobs = newFilteredJobs.filter(
        (job) => job.jobType.toLowerCase() === jobType.toLowerCase()
      );
    }
    if (minSalary) {
      newFilteredJobs = newFilteredJobs.filter(
        (job) => job.salary >= parseFloat(minSalary)
      );
    }
    if (maxSalary) {
      newFilteredJobs = newFilteredJobs.filter(
        (job) => job.salary <= parseFloat(maxSalary)
      );
    }

    console.log('Filtered Jobs:', newFilteredJobs); // Debugging

    setFilteredJobs(newFilteredJobs);
  }, [jobs, role, jobType, minSalary, maxSalary]);

  useEffect(() => {
    filterJobs();
  }, [filterJobs]);

  const resetFilters = useCallback(() => {
    setLocation('');
    setRole('');
    setJobType('');
    setMinSalary('');
    setMaxSalary('');
    setFilteredJobs(jobs);
  }, [jobs]);

  const handleSearchClick = async () => {
    if (location) {
      const { lat, lon } = await geocodeAddress(location);
      setMapCenter([lat, lon]);
      setMapZoom(11); // Only zoom the map
    }
  };

  const offsetCoordinates = (lat, lon, index, count) => {
    const offset = 0.0001;
    const angle = (2 * Math.PI * index) / count;
    return {
      lat: lat + offset * Math.sin(angle),
      lon: lon + offset * Math.cos(angle),
    };
  };

  const groupedJobs = filteredJobs.reduce((acc, job) => {
    const key = `${job.latitude},${job.longitude}`;
    if (!acc[key]) {
      acc[key] = [];
    }
    acc[key].push(job);
    return acc;
  }, {});

  const UpdateMapView = ({ center, zoom }) => {
    const map = useMap();
    useEffect(() => {
      map.setView(center, zoom, { animate: true });
    }, [center, zoom, map]);
    return null;
  };

  return (
    <>
      <UserNavbar />
      <Container maxWidth="lg" sx={{ marginTop: '20px' }}>
        <Paper
          sx={{
            padding: '20px',
            marginBottom: '20px',
            borderRadius: '10px',
            boxShadow: '0px 4px 10px rgba(0, 0, 0, 0.1)',
            backgroundColor: '#f5f5f5',
          }}
        >
          <Typography variant="h4" align="center" gutterBottom>
            Job Map View
          </Typography>
          <Grid
            container
            spacing={2}
            alignItems="center"
            justifyContent="center"
          >
            <Grid item xs={12} md={6} lg={2}>
              <TextField
                label="Location"
                variant="outlined"
                fullWidth
                value={location}
                onChange={(e) => setLocation(e.target.value)}
              />
            </Grid>
            <Grid item xs={12} md={6} lg={2}>
              <TextField
                label="Role"
                variant="outlined"
                fullWidth
                value={role}
                onChange={(e) => setRole(e.target.value)}
              />
            </Grid>
            <Grid item xs={12} md={6} lg={2}>
              <FormControl variant="outlined" fullWidth>
                <InputLabel>Job Type</InputLabel>
                <Select
                  value={jobType}
                  onChange={(e) => setJobType(e.target.value)}
                  label="Job Type"
                >
                  <MenuItem value="">All</MenuItem>
                  <MenuItem value="Full Time">Full-time</MenuItem>
                  <MenuItem value="Part Time">Part-time</MenuItem>
                  <MenuItem value="Internship">Internship</MenuItem>
                  <MenuItem value="Contract">Contract</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={6} md={3} lg={2}>
              <TextField
                label="Min Salary"
                type="number"
                variant="outlined"
                fullWidth
                value={minSalary}
                onChange={(e) => setMinSalary(e.target.value)}
              />
            </Grid>
            <Grid item xs={6} md={3} lg={2}>
              <TextField
                label="Max Salary"
                type="number"
                variant="outlined"
                fullWidth
                value={maxSalary}
                onChange={(e) => setMaxSalary(e.target.value)}
              />
            </Grid>
            <Grid item xs={12} md={6} lg={2} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Tooltip title="Search">
                <IconButton
                  color="primary"
                  onClick={handleSearchClick}
                  sx={{ borderRadius: '50%' }}
                >
                  <FaSearch />
                </IconButton>
              </Tooltip>
              <Tooltip title="Reset Filters">
                <IconButton
                  color="secondary"
                  onClick={resetFilters}
                  sx={{ borderRadius: '50%' }}
                >
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
            </Grid>
          </Grid>
        </Paper>

        <MapContainer
          center={mapCenter}
          zoom={mapZoom}
          style={{ height: '100vh', width: '100%' }}
        >
          <TileLayer
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          />
          <UpdateMapView center={mapCenter} zoom={mapZoom} />
          {Object.entries(groupedJobs).map(([key, jobs], index) => {
            const firstJob = jobs[0];
            const offsetCoords = offsetCoordinates(
              firstJob.latitude,
              firstJob.longitude,
              index,
              jobs.length
            );

            return (
              <Marker
                key={`group-${key}`}
                position={[offsetCoords.lat, offsetCoords.lon]}
              >
                <Popup>
                  <div className="popup-content">
                    {jobs.map((job, i) => (
                      <div key={job.id}>
                        <strong>{job.companyName}</strong>
                        <br />
                        Role: {job.role}
                        <br />
                        Start Date: {job.startDate}
                        <br />
                        Apply By: {job.applyBy}
                        <br />
                        Salary: {job.salary}
                        <br />
                        <button
                          onClick={() => navigate(`/usergetlist/${job.id}`)}
                          style={{
                            backgroundColor: '#007bff',
                            color: '#fff',
                            border: 'none',
                            padding: '5px 10px',
                            borderRadius: '5px',
                            cursor: 'pointer',
                            marginTop: '5px',
                          }}
                        >
                          View Details
                        </button>
                        {i < jobs.length - 1 && (
                          <hr className="job-divider" />
                        )}
                      </div>
                    ))}
                  </div>
                </Popup>
              </Marker>
            );
          })}
        </MapContainer>
      </Container>
      <UserFooter />
    </>
  );
};

export default MapView;
