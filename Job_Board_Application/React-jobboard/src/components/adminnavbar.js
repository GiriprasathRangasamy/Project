import React, { useState, useEffect } from 'react';
import './adminnavbar.css';
import img from '../components/images/img3.jpeg';
import { AccountCircle } from '@mui/icons-material';
import { Popover, Button, Typography, Modal, TextField, Snackbar, Alert } from '@mui/material';
import axios from 'axios';
import { useRecemail } from '../context/recruiterauth';
import { useNavigate } from 'react-router-dom';

function AdminNavbar() {
  const [anchorEl, setAnchorEl] = useState(null);
  const [openModal, setOpenModal] = useState(false);
  const [user, setUser] = useState({
    email: '', // Default value; replace with actual user context if available
    name: '',
    mobile: '',
    company: '',
    password: '',
  });
  const [loading, setLoading] = useState(true); // Loading state
  const [snackbarOpen, setSnackbarOpen] = useState(false); // Snackbar state for notifications
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState('success');
  const { recemail,setRecemail } = useRecemail();
  const navigate=useNavigate();
  // Fetch user details by email
  useEffect(() => {
    // Simulate fetching logged-in user email
    const email = recemail;
    console.log(email);
    axios
      .get(`http://localhost:8080/recruiter/logindetails/${email}`)
      .then((response) => {
        setUser(response.data);
        setLoading(false);
      })
      .catch((error) => {
        console.error('Error fetching user data:', error);
        setLoading(false);
        setSnackbarMessage('Failed to load user data');
        setSnackbarSeverity('error');
        setSnackbarOpen(true);
      });
  }, []);

  // Handle popover open/close
  const handlePopoverOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handlePopoverClose = () => {
    setAnchorEl(null);
  };

  const open = Boolean(anchorEl);

  // Handle modal open/close
  const handleModalOpen = () => {
    setOpenModal(true);
    handlePopoverClose(); // Close popover when modal is opened
  };

  const handleModalClose = () => {
    setOpenModal(false);
  };

  // Handle logout (Replace with actual logic)
  const handleLogout = () => {
    console.log('Logout clicked');
    
    // Clear the token and any other stored data
    localStorage.removeItem('token');
    localStorage.removeItem('Payload');
    setRecemail("");
  
    // Navigate to the homepage or login page after logout
    navigate("/");
  
    // Provide feedback to the user via Snackbar
    setSnackbarMessage('Logged out successfully');
    setSnackbarSeverity('success');
    setSnackbarOpen(true);
  };

  // Handle form input changes
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setUser({ ...user, [name]: value });
  };

  // Handle form submission for saving user details
  const handleFormSubmit = async (event) => {
    event.preventDefault();

    const updatedData = {
    email:user.email,
      name: user.name,
      mobile: user.mobile,
      company: user.company,
      password: user.password, // Update password if needed
    };

    await fetch("http://localhost:8081/security/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updatedData)
    })
      .then((response) => {
        console.log('User updated successfully:', response.data);
        setSnackbarMessage('User details updated successfully');
        setSnackbarSeverity('success');
        setSnackbarOpen(true);
        handleModalClose(); 
      })
      .catch((error) => {
        console.error('Error updating user data:', error);
        setSnackbarMessage('Failed to update user details');
        setSnackbarSeverity('error');
        setSnackbarOpen(true);
      });
  };

  // Handle Snackbar close
  const handleSnackbarClose = () => {
    setSnackbarOpen(false);
  };

  return (
    <div id='nav2'>
      <div id='icon'>
        <img src={img} id='img1' alt='logo' />
        <h1 style={{ fontFamily: 'unset' }}>SkillMatch</h1>
      </div>
      <div className='link'>
        <h2><a href='/adminpostlist'>Home</a></h2>
        <h2><a href='/adminaddpost'>Create Job</a></h2>
      </div>
      <div className='user'>
        <AccountCircle
          sx={{
            fontSize: '3em',
            color: 'black',
            cursor: 'pointer', // Make icon clickable
          }}
          onClick={handlePopoverOpen} // Open popover on click
        />
        {/* Popover for account details */}
        <Popover
          open={open}
          anchorEl={anchorEl}
          onClose={handlePopoverClose}
          anchorOrigin={{
            vertical: 'bottom',
            horizontal: 'center',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'center',
          }}
        >
          <div style={{ padding: '1em'}}>
            <Typography variant='h6'>{user.name}</Typography>
            <Typography variant='body1'>{user.email}</Typography>
            <Button variant='contained' color='primary' onClick={handleModalOpen}>
              View Details
            </Button>
            <Button variant='contained' color='secondary' onClick={handleLogout} style={{ marginLeft: '0.5em' }}>
              Logout
            </Button>
          </div>
        </Popover>
      </div>

      {/* Modal for detailed account view */}
      <Modal
        open={openModal}
        onClose={handleModalClose}
        aria-labelledby='user-details-title'
        aria-describedby='user-details-description'
      >
        <div className='modal-content' style={modalStyle}>
          <h2 id='user-details-title'>User Details</h2>
          {loading ? (
            <Typography variant="body1">Loading...</Typography>
          ) : (
            <form onSubmit={handleFormSubmit}>
              <TextField
                label='Email'
                defaultValue={user.email}
                fullWidth
                margin='normal'
                disabled // Disable editing for the email field
              />
              <TextField
                label='Name'
                name='name'
                value={user.name}
                onChange={handleInputChange}
                fullWidth
                margin='normal'
              />
              <TextField
                label='Mobile'
                name='mobile'
                value={user.mobile}
                onChange={handleInputChange}
                fullWidth
                margin='normal'
              />
              <TextField
                label='Company'
                name='company'
                value={user.company}
                onChange={handleInputChange}
                fullWidth
                margin='normal'
              />
              <TextField
                label='Password'
                name='password'
                value={user.password}
                onChange={handleInputChange}
                fullWidth
                margin='normal'
                type='password'
              
              />
              <Button type='submit' variant='contained' color='primary' style={{ marginTop: '1em' }}>
                Save
              </Button>
            </form>
          )}
        </div>
      </Modal>

      {/* Snackbar for feedback */}
      <Snackbar
        open={snackbarOpen}
        autoHideDuration={6000}
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert onClose={handleSnackbarClose} severity={snackbarSeverity} sx={{ width: '100%' }}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </div>
  );
}

// Modal styling
const modalStyle = {
  position: 'absolute',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  width: '400px',
  backgroundColor: 'white',
  padding: '2em',
  boxShadow: '24px',
  borderRadius: '8px',
};

export default AdminNavbar;
