import React, { useState } from 'react';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useResume } from '../context/ResumeContext';

function Achievements() {
  const { addAchievement, resumeData, removeAchievement } = useResume();
  const [achievement, setAchievement] = useState('');

  const handleAddAchievement = () => {
    if (achievement.trim()) {
      addAchievement(achievement);
      setAchievement('');
    }
  };

  return (
    <Box mb={2} p={2} border={1} borderRadius={2} borderColor="grey.300" boxShadow={2} sx={{background:'white'}}>
      <Typography variant="h6" gutterBottom>Achievements</Typography>
      <TextField
        label="Achievement"
        variant="outlined"
        fullWidth
        margin="normal"
        value={achievement}
        onChange={(e) => setAchievement(e.target.value)}
      />
      <Button variant="contained" color="primary" onClick={handleAddAchievement}>Add Achievement</Button>
      <Box mt={2}>
        {resumeData.achievements.map((ach, index) => (
          <Box key={index} display="flex" justifyContent="space-between" alignItems="center" mb={1}>
            <Typography variant="body1">{ach}</Typography>
            <Button color="error" onClick={() => removeAchievement(index)}>Remove</Button>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

export default Achievements;
