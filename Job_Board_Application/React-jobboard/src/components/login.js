import React, { useState } from 'react';
import { TextField, Button, Box, Typography } from '@mui/material';
import { AccountCircle } from '@mui/icons-material';
import './login.css';
import Navbar from './Navbar';
import Footer from './footer';
import loginimage from './images/loginimg.jpg'
import { useRecemail } from '../context/recruiterauth';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const LoginForm = () => {
  const { setRecemail } = useRecemail();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  function base64UrlDecode(base64Url) {
    base64Url = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const base64 = atob(base64Url);
    try {
      return decodeURIComponent(
        base64
          .split('')
          .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
    } catch (err) {
      return base64;
    }
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      const res = await axios.post("http://localhost:8081/security/authenticate", {
        email, password
      });
      console.log(res);
      const alert1=res.data.alert;
      alert(alert1);
      if(alert1=="Login successful")
      {
      const token = res.data.access_token;
      console.log(token);
      localStorage.setItem("token", token);

      const [header, payload] = token.split('.');
      const decodedPayload = base64UrlDecode(payload);
      const payloadObject = JSON.parse(decodedPayload);

      localStorage.setItem('Payload', JSON.stringify(payloadObject));
      setRecemail(email);
      navigate('/adminpostlist');}
    } catch (err) {
      console.log(err);
      setError("An error occurred during sign in");
    }
  };

  return (
    <div className='fullpage'>
      <Navbar />
      <div className="root">
        <Box className="form">
          <Box className="icon-container">
            <AccountCircle sx={{ fontSize: '50px', color: 'primary.main' }} />
          </Box>
          <Typography component="h1" variant="h5" align="center">
            Login
          </Typography>
          {error && <Typography className="error">{error}</Typography>}
          <form onSubmit={handleSubmit}>
            <TextField
              variant="outlined"
              margin="normal"
              required
              fullWidth
              id="email"
              label="Email Address"
              name="email"
              autoComplete="email"
              autoFocus
              type='email'
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <TextField
              variant="outlined"
              margin="normal"
              required
              fullWidth
              name="password"
              label="Password"
              type="password"
              id="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <Button
              type="submit"
              fullWidth
              variant="contained"
              className="submit"
            >
              Login
            </Button>
          </form>
          <Box className="signup-container">
            <Typography variant="body2" color="textSecondary">
              New to Job Board?....
            </Typography>
            <Button
              variant="contained"
              href='/adminsignup'
              className="signup-button"
              sx={{ backgroundColor: "#fada4b" }}
            >
              Sign Up
            </Button>
          </Box>
        </Box>
      </div>
      <Footer />
    </div>
  );
};

export default LoginForm;