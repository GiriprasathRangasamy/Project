import React, { useState } from 'react';
import { Box, Button, TextField, Typography, List, ListItem, IconButton } from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import { useResume } from '../context/ResumeContext';

const Education = () => {
  const { resumeData, addEducation, removeEducation } = useResume();
  const [newEducation, setNewEducation] = useState({
    degree: '',
    institution: '',
    dateRange: '',
    description: '',
    mark: '',
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setNewEducation({ ...newEducation, [name]: value });
  };

  const handleAdd = () => {
    addEducation(newEducation);
    setNewEducation({
      degree: '',
      institution: '',
      dateRange: '',
      description: '',
      mark: '',
    });
  };

  return (
    <Box mb={4} p={2} border={1} borderRadius={2} borderColor="grey.300" boxShadow={2} sx={{background:'white'}}>
      <Typography variant="h5" sx={{ color: '#1976d2' }}>Education</Typography>
      <Box>
        <TextField
          name="degree"
          label="Degree"
          variant="outlined"
          fullWidth
          margin="normal"
          value={newEducation.degree}
          onChange={handleChange}
        />
        <TextField
          name="institution"
          label="Institution"
          variant="outlined"
          fullWidth
          margin="normal"
          value={newEducation.institution}
          onChange={handleChange}
        />
        <TextField
          name="dateRange"
          label="Date Range"
          variant="outlined"
          fullWidth
          margin="normal"
          value={newEducation.dateRange}
          onChange={handleChange}
        />
        <TextField
          name="description"
          label="Description"
          variant="outlined"
          fullWidth
          margin="normal"
          value={newEducation.description}
          onChange={handleChange}
        />
        <TextField
          name="mark"
          label="Mark"
          variant="outlined"
          fullWidth
          margin="normal"
          value={newEducation.mark}
          onChange={handleChange}
        />
        <Button variant="contained" color="primary" onClick={handleAdd}>
          Add Education
        </Button>
      </Box>
      <List>
        {resumeData.education.map((edu, index) => (
          <ListItem key={index} sx={{ paddingY: 1, display: 'flex', alignItems: 'center' }}>
            <Box flexGrow={1}>
              <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                {edu.degree || 'Degree'} from {edu.institution || 'Institution'}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {edu.dateRange || 'Date Range'}
              </Typography>
              <Typography variant="body2">
                {edu.description || 'Description'}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {edu.mark || 'Mark'}
              </Typography>
            </Box>
            <IconButton color="error" onClick={() => removeEducation(index)}>
              <DeleteIcon />
            </IconButton>
          </ListItem>
        ))}
      </List>
    </Box>
  );
};

export default Education;
