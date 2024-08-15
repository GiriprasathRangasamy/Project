import React, { useState } from 'react';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import DeleteIcon from '@mui/icons-material/Delete';
import { useResume } from '../context/ResumeContext';

function Experience() {
  const { addExperience, removeExperience, hideSection } = useResume();
  const [jobTitle, setJobTitle] = useState('');
  const [company, setCompany] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [description, setDescription] = useState('');

  const handleAddExperience = () => {
    if (jobTitle && company && startDate && endDate && description) {
      addExperience({ jobTitle, company, startDate, endDate, description });
      setJobTitle('');
      setCompany('');
      setStartDate('');
      setEndDate('');
      setDescription('');
    }
  };

  const handleRemoveExperienceComponent = () => {
    hideSection('experience'); // Hide the Experience component
  };

  return (
    <Box p={3} border={1} borderRadius={2} borderColor="grey.300" boxShadow={2} sx={{background:'white'}}>
      <Typography variant="h6">Experience</Typography>
      <TextField
        label="Job Title"
        variant="outlined"
        fullWidth
        margin="normal"
        value={jobTitle}
        onChange={(e) => setJobTitle(e.target.value)}
      />
      <TextField
        label="Company"
        variant="outlined"
        fullWidth
        margin="normal"
        value={company}
        onChange={(e) => setCompany(e.target.value)}
      />
      <TextField
        label="Start Date"
        variant="outlined"
        fullWidth
        margin="normal"
        value={startDate}
        onChange={(e) => setStartDate(e.target.value)}
      />
      <TextField
        label="End Date"
        variant="outlined"
        fullWidth
        margin="normal"
        value={endDate}
        onChange={(e) => setEndDate(e.target.value)}
      />
      <TextField
        label="Description"
        variant="outlined"
        fullWidth
        margin="normal"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
      />
      <Button
        variant="contained"
        color="primary"
        fullWidth
        onClick={handleAddExperience}
      >
        Add Experience
      </Button>
      <ExperienceList removeExperience={removeExperience} />
      <IconButton onClick={handleRemoveExperienceComponent} color="error">
        <DeleteIcon />
      </IconButton>
    </Box>
  );
}

function ExperienceList({ removeExperience }) {
  const { resumeData } = useResume();

  return (
    <Box mt={2}>
      <Typography variant="h6">Experience List</Typography>
      {resumeData.experience.length > 0 ? (
        resumeData.experience.map((exp, index) => (
          <Box key={index} display="flex" alignItems="center" mb={1} p={1} border={1} borderColor="grey.300" borderRadius={1}>
            <Box flexGrow={1}>
              <Typography variant="body1"><strong>{exp.jobTitle}</strong></Typography>
              <Typography variant="body2">{exp.company}</Typography>
              <Typography variant="body2">{exp.startDate} - {exp.endDate}</Typography>
              <Typography variant="body2">{exp.description}</Typography>
            </Box>
            <IconButton onClick={() => removeExperience(index)} color="error">
              <DeleteIcon />
            </IconButton>
          </Box>
        ))
      ) : (
        <Typography variant="body2">No experience entries added yet.</Typography>
      )}
    </Box>
  );
}

export default Experience;
