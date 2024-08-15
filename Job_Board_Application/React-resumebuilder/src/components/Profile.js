import React, { useState } from 'react';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Avatar from '@mui/material/Avatar';
import { useResume } from '../context/ResumeContext';

function Profile() {
  const { updateProfile } = useResume();
  const [profile, setProfile] = useState({
    image: null,
    name: '',
    email: '',
    phone: '',
    github: '',
    linkedin: '',
    address: '',
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setProfile({ ...profile, [name]: value });
  };

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setProfile({ ...profile, image: reader.result });
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSubmit = () => {
    updateProfile(profile);
  };

  return (
    <Box mb={2} p={2} border={1} borderRadius={2} borderColor="grey.300" boxShadow={2} sx={{background:'white'}}>
      <Typography variant="h6" gutterBottom>Profile</Typography>
      
      <Box mb={2} textAlign="center">
        <Avatar
          src={profile.image}
          alt="Profile Picture"
          sx={{ width: 120, height: 120, margin: 'auto', border: '2px solid #1976d2' }}
        />
        <Button
          variant="contained"
          component="label"
          sx={{ mt: 1 }}
        >
          Upload Photo
          <input
            type="file"
            hidden
            accept="image/*"
            onChange={handleImageChange}
          />
        </Button>
      </Box>

      <TextField
        label="Name"
        name="name"
        variant="outlined"
        fullWidth
        margin="normal"
        value={profile.name}
        onChange={handleChange}
      />
      <TextField
        label="Email"
        name="email"
        variant="outlined"
        fullWidth
        margin="normal"
        value={profile.email}
        onChange={handleChange}
      />
      <TextField
        label="Phone"
        name="phone"
        variant="outlined"
        fullWidth
        margin="normal"
        value={profile.phone}
        onChange={handleChange}
      />
      <TextField
        label="GitHub URL"
        name="github"
        variant="outlined"
        fullWidth
        margin="normal"
        value={profile.github}
        onChange={handleChange}
      />
      <TextField
        label="LinkedIn URL"
        name="linkedin"
        variant="outlined"
        fullWidth
        margin="normal"
        value={profile.linkedin}
        onChange={handleChange}
      />
      <TextField
        label="Address"
        name="address"
        variant="outlined"
        fullWidth
        margin="normal"
        multiline
        rows={3}
        value={profile.address}
        onChange={handleChange}
      />
      <Button variant="contained" color="primary" fullWidth onClick={handleSubmit}>
        Update Profile
      </Button>
    </Box>
  );
}

export default Profile;
