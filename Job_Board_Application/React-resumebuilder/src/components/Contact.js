import React from 'react';
import { useResume } from '../context/ResumeContext';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Link from '@mui/material/Link';

function Contact() {
  const { resumeData } = useResume();

  return (
    <Box mb={2} p={2} border={1} borderRadius={2} borderColor="grey.300" boxShadow={2} sx={{background:'white'}}>
      <Typography variant="h6" gutterBottom>Contact Information</Typography>
      {resumeData.profile?.address && (
        <Typography variant="body1" paragraph>
          <strong>Address:</strong> {resumeData.profile.address}
        </Typography>
      )}
      {resumeData.profile?.github && (
        <Typography variant="body1" paragraph>
          <strong>GitHub:</strong>{' '}
          <Link href={resumeData.profile.github} target="_blank" rel="noopener" color="primary">
            {resumeData.profile.github}
          </Link>
        </Typography>
      )}
      {resumeData.profile?.linkedin && (
        <Typography variant="body1" paragraph>
          <strong>LinkedIn:</strong>{' '}
          <Link href={resumeData.profile.linkedin} target="_blank" rel="noopener" color="primary">
            {resumeData.profile.linkedin}
          </Link>
        </Typography>
      )}
      {resumeData.profile?.google && (
        <Typography variant="body1" paragraph>
          <strong>Google:</strong>{' '}
          <Link href={resumeData.profile.google} target="_blank" rel="noopener" color="primary">
            {resumeData.profile.google}
          </Link>
        </Typography>
      )}
    </Box>
  );
}

export default Contact;
