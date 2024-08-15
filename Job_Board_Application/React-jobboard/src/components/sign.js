import React, { useState } from 'react';
import {
  TextField,
  Button,
  IconButton,
  InputAdornment,
  Typography,
  Container,
  Box,
} from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import signinimage from './images/login1.jpeg';

const SignUpForm = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    mobile: '',
    password: '',
    confirmPassword: '',
    company: ''
  });

  const [showPassword, setShowPassword] = useState(false);
  const [passwordError, setPasswordError] = useState('');

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });

    if (e.target.name === 'password') {
      validatePassword(e.target.value);
    }
  };

  const validatePassword = (password) => {
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!regex.test(password)) {
      setPasswordError(
        'Password must be at least 8 characters long, contain 1 uppercase letter, 1 lowercase letter, 1 number, and 1 symbol.'
      );
    } else {
      setPasswordError('');
    }
  };

  const handleClickShowPassword = () => {
    setShowPassword(!showPassword);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (formData.password !== formData.confirmPassword) {
      alert('Passwords do not match!');
      return;
    }

    if (passwordError) {
      alert('Please fix the password errors before submitting.');
      return;
    }

    const userdata = {
      name: formData.name,
      email: formData.email,
      mobile: formData.mobile,
      password: formData.password,
      company: formData.company,
      role: "ADMIN",
    };

    const response = await fetch("http://localhost:8081/security/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(userdata)
    });

    const responsebody = await response.text();
    if (responsebody) {
      alert("Register Successful");
      navigate('/adminlogin');
    } else {
      alert("User already exists");
    }
  };

  return (
    <div style={{ backgroundImage: `url(${signinimage})` }}>
      <Container maxWidth="xs">
        <Box
          display="flex"
          flexDirection="column"
          justifyContent="center"
          alignItems="center"
          minHeight="100vh"
        >
          <Box
            sx={{
              p: 4,
              border: '1px solid',
              borderColor: 'grey.300',
              borderRadius: 2,
              boxShadow: 3,
              width: '100%',
              backgroundColor: 'white',
            }}
          >
            <Typography variant="h4" component="h1" gutterBottom align="center">
              Sign Up
            </Typography>
            <form onSubmit={handleSubmit}>
              <TextField
                fullWidth
                margin="normal"
                label="Name"
                name="name"
                variant="outlined"
                value={formData.name}
                onChange={handleChange}
              />
              <TextField
                fullWidth
                margin="normal"
                label="Email"
                name="email"
                type="email"
                variant="outlined"
                value={formData.email}
                onChange={handleChange}
              />
              <TextField
                fullWidth
                margin="normal"
                label="Mobile Number"
                name="mobile"
                type="tel"
                variant="outlined"
                value={formData.mobile}
                onChange={handleChange}
              />
              <TextField
                fullWidth
                margin="normal"
                label="Password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                variant="outlined"
                value={formData.password}
                onChange={handleChange}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        aria-label="toggle password visibility"
                        onClick={handleClickShowPassword}
                        edge="end"
                      >
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                error={!!passwordError}
                helperText={passwordError}
              />
              <TextField
                fullWidth
                margin="normal"
                label="Confirm Password"
                name="confirmPassword"
                type="password"
                variant="outlined"
                value={formData.confirmPassword}
                onChange={handleChange}
              />
              <TextField
                fullWidth
                margin="normal"
                label="Company Name"
                name="company"
                variant="outlined"
                value={formData.company}
                onChange={handleChange}
              />
              <Button
                fullWidth
                type="submit"
                variant="contained"
                color="primary"
                sx={{ mt: 2 }}
              >
                Sign Up
              </Button>
            </form>
          </Box>
        </Box>
      </Container>
    </div>
  );
};

export default SignUpForm;
