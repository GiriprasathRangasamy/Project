import React, { useState } from 'react';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useResume } from '../context/ResumeContext';

function Projects() {
  const { addProject, resumeData, removeProject } = useResume();
  const [project, setProject] = useState({ title: '', description: '', link: '' });

  const handleAddProject = () => {
    if (project.title.trim() && project.link.trim()) {
      addProject(project);
      setProject({ title: '', description: '', link: '' });
    }
  };

  return (
    <Box mb={2} p={2} border={1} borderRadius={2} borderColor="grey.300" boxShadow={2} sx={{background:'white'}}>
      <Typography variant="h6" gutterBottom>Projects</Typography>
      <TextField
        label="Title"
        name="title"
        variant="outlined"
        fullWidth
        margin="normal"
        value={project.title}
        onChange={(e) => setProject({ ...project, title: e.target.value })}
      />
      <TextField
        label="Description"
        name="description"
        variant="outlined"
        fullWidth
        margin="normal"
        value={project.description}
        onChange={(e) => setProject({ ...project, description: e.target.value })}
      />
      <TextField
        label="Link"
        name="link"
        variant="outlined"
        fullWidth
        margin="normal"
        value={project.link}
        onChange={(e) => setProject({ ...project, link: e.target.value })}
      />
      <Button variant="contained" color="primary" onClick={handleAddProject}>Add Project</Button>
      <Box mt={2}>
        {resumeData.projects.map((proj, index) => (
          <Box key={index} display="flex" justifyContent="space-between" alignItems="center" mb={1}>
            <Box>
              <Typography variant="body1" sx={{ fontWeight: 'bold' }}>{proj.title}</Typography>
              <Typography variant="body2">{proj.description}</Typography>
              <Button color="primary" href={proj.link} target="_blank">View Project</Button>
            </Box>
            <Button color="error" onClick={() => removeProject(index)}>Remove</Button>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

export default Projects;
