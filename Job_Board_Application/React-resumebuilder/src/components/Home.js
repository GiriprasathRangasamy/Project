import React from 'react'
import Profile from './Profile'
import Experience from './Experience'
import Education from './Education'
import Skills from './Skills'
import Projects from './Projects'
import Achievements from './Achievements'
import Contact from './Contact'
import ResumePreview from './ResumePreview'
import { Box, Button, Container, Grid, Typography } from '@mui/material'
import { useResume } from '../context/ResumeContext'
import { Link } from 'react-router-dom'

export const Home = () => {
  const{setLoader}=useResume();
  const buttonStyles = {
    backgroundColor: '#4CAF50', // Green background
    border: 'none', // Remove borders
    color: 'white', // White text
    padding: '15px 32px', // Some padding
    textAlign: 'center', // Centered text
    textDecoration: 'none', // Remove underline
    display: 'inline-block', // Make the buttons appear next to each other
    fontSize: '16px', // Increase font size
    margin: '4px 2px', // Add some margin
    cursor: 'pointer', // Pointer/hand icon
    borderRadius: '12px', // Rounded corners
    transition: 'background-color 0.3s ease', // Smooth transition
    marginLeft:"12vw",
  };
  return (
    <div className='home'>
 <Container>
        <Box py={4}>
          <Grid container spacing={4}>
            <Grid item xs={12} md={6}>
              <Profile />
            
              <Experience />
              <Education/>
              <Skills/>
              <Projects />
              <Achievements />
              <Contact />
            </Grid>
            <Grid item xs={12} md={6}>
              <ResumePreview />
              <Button onClick={()=>setLoader(true)} variant="contained" color="primary" style={{marginTop:"10px", marginLeft:"10vw"}}>Show Buttons in Preview</Button>
              <Typography variant="h6">
          <Link to='http://localhost:3000/resumeanylser'>
          <button style={buttonStyles}>

          Resume Analyser
          </button>
          </Link>
        </Typography>
            </Grid>
          </Grid>
        </Box>
      </Container>
    </div>
  )
}
