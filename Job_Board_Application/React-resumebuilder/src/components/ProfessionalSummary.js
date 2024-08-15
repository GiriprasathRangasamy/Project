import React from 'react';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';

function ProfessionalSummary() {
  return (
    <Box sx={{background:'white'}}>
      <TextField
        label="Professional Summary"
        multiline
        rows={4}
        variant="outlined"
        fullWidth
        margin="normal"
      />
    </Box>
  );
}

export default ProfessionalSummary;
