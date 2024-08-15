import React from 'react';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';

function Header() {
  
  return (
    <AppBar position="static">
      <Toolbar sx={{display:'flex',justifyContent:'space-around'}}>
        <Typography variant="h6">
          Resume Builder
        </Typography>
        
      </Toolbar>
    </AppBar>
  );
}

export default Header;
