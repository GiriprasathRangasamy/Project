import React, { useState } from 'react';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useResume } from '../context/ResumeContext';

function Skills() {
  const { addSkill, resumeData, removeSkill } = useResume();
  const [skill, setSkill] = useState('');

  const handleAddSkill = () => {
    if (skill.trim()) {
      addSkill(skill);
      setSkill('');
    }
  };

  return (
    <Box mb={2} p={2} border={1} borderRadius={2} borderColor="grey.300" boxShadow={2} sx={{background:'white'}}>
      <Typography variant="h6" gutterBottom>Skills</Typography>
      <TextField
        label="Skill"
        variant="outlined"
        fullWidth
        margin="normal"
        value={skill}
        onChange={(e) => setSkill(e.target.value)}
      />
      <Button variant="contained" color="primary" onClick={handleAddSkill}>Add Skill</Button>
      <Box mt={2}>
        {resumeData.skills.map((skill, index) => (
          <Box key={index} display="flex" justifyContent="space-between" alignItems="center" mb={1}>
            <Typography variant="body1">{skill}</Typography>
            <Button color="error" onClick={() => removeSkill(index)}>Remove</Button>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

export default Skills;
