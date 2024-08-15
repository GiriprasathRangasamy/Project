import React, { useState } from 'react';
import { useResume } from '../context/ResumeContext';
import Avatar from '@mui/material/Avatar';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import Link from '@mui/material/Link';
import Divider from '@mui/material/Divider';
import Paper from '@mui/material/Paper';
import Button from '@mui/material/Button';
import html2pdf from 'html2pdf.js';
import { ChromePicker } from 'react-color'; // Import ChromePicker
import './ResumePreview.css'; // Import the CSS file

function ResumePreview() {
  const { loader,setLoader,resumeData, sectionsVisible = {} } = useResume();
  const [bgColor, setBgColor] = useState(''); // Default background color
  const [textColor, setTextColor] = useState('#1976d2'); // Default text color
  const [pickerVisible, setPickerVisible] = useState(false);

  const handleDownloadPDF = () => {
    setLoader(false);
    const element = document.getElementById('resume-preview');
    const options = {
      margin: [0, 0, 0, 0],
      filename: 'resume.pdf',
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: {
        scale: 3, // Scale down for better fit
        logging: true,
        scrollX: 0,
        scrollY: 0,
        useCORS: true
      },
      jsPDF: {
        unit: 'pt',
        format: [612, 792], // 8.5 x 11 inches in points
        orientation: 'portrait'
      }
    };
    html2pdf().from(element).set(options).save();
  };

  const handleColorChange = (color, type) => {
    if (type === 'background') {
      setBgColor(color.hex);
    } else if (type === 'text') {
      setTextColor(color.hex);
    }
  };

  const togglePicker = () => {
    setPickerVisible(!pickerVisible);
  };

  if (!resumeData) {
    return <Typography variant="body1">No resume data available</Typography>;
  }

  const {
    professionalSummary = false,
    experience = false,
    education = false,
    skills = false,
    projects = false,
    achievements = false
  } = sectionsVisible;

  return (
    <Paper
      elevation={3}
      sx={{
        padding: 3,
        borderRadius: 2,
        maxWidth: '612pt',
        margin: 'auto',
        backgroundColor: bgColor
      }}
      id="resume-preview"
    >
      <Box mb={1.4} textAlign="center">
        <div style={{ display: 'flex', justifyContent: 'space-around' }}>
          <div>
            <Avatar
              src={resumeData.profile?.image}
              alt="Profile Picture"
              sx={{ width: 100, height: 100, margin: 'auto', border: `3px solid ${textColor}` }}
            />
          </div>
          <div>
            <Typography variant="h5" gutterBottom sx={{ color: textColor }}>
              {resumeData.profile?.name || 'No Name Provided'}
            </Typography>
            <Typography variant="body1" color="text.secondary">
              {resumeData.profile?.email || 'No Email Provided'}
            </Typography>
            <Typography variant="body1" color="text.secondary">
              {resumeData.profile?.phone || 'No Phone Provided'}
            </Typography>
          </div>
        </div>
      </Box>

      <Box mb={2.5}>
        <hr></hr>
        <Typography variant="h6" sx={{ color: textColor }}>Contact Information</Typography>
        {resumeData.profile?.address && (
          <Typography variant="body2" paragraph>
            <strong>Address:</strong> {resumeData.profile.address}
          </Typography>
        )}
        {resumeData.profile?.github && (
          <Typography variant="body2" sx={{ marginTop: '-11px' }} paragraph>
            <strong>GitHub:</strong>{' '}
            <Link href={resumeData.profile.github} target="_blank" rel="noopener" color="primary">
              {resumeData.profile.github}
            </Link>
          </Typography>
        )}
        {resumeData.profile?.linkedin && (
          <Typography variant="body2" sx={{ marginTop: '-11px' }} paragraph>
            <strong>LinkedIn:</strong>{' '}
            <Link href={resumeData.profile.linkedin} target="_blank" rel="noopener" color="primary">
              {resumeData.profile.linkedin}
            </Link>
          </Typography>
        )}
        {resumeData.profile?.google && (
          <Typography variant="body2" paragraph>
            <strong>Google:</strong>{' '}
            <Link href={resumeData.profile.google} target="_blank" rel="noopener" color="primary">
              {resumeData.profile.google}
            </Link>
          </Typography>
        )}
      </Box>


      {experience && resumeData.experience?.length > 0 && (
        <Box mb={1} sx={{ margin: '-15px 0px' }}>
          <Typography variant="h6" sx={{ color: textColor, marginTop: '-10px' }}>Experience</Typography>
          <Divider sx={{ marginY: 0 }} />
          <List>
            {resumeData.experience.map((exp, index) => (
              <ListItem key={index} sx={{ paddingY: .5, marginTop: '-10px' }}>
                <Box flexGrow={1}>
                  <Typography variant="body1" sx={{ fontWeight: 'bold', color: 'black' }}>
                    {exp.jobTitle || 'No Job Title'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {exp.company || 'No Company'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {exp.startDate || 'No Start Date'} - {exp.endDate || 'No End Date'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {exp.description || 'No Description'}
                  </Typography>
                </Box>
              </ListItem>
            ))}
          </List>
        </Box>
      )}


      {education && resumeData.education.length > 0 && (
        <Box mb={2}>
          <Typography variant="h6" sx={{ color: textColor, marginTop: '-10px' }}>Education</Typography>
          <Divider sx={{ marginY: 0 }} />
          {resumeData.education.map((edu, index) => (
            <Box key={index} mb={2}>
              <Typography variant="body1" sx={{ fontWeight: 'bold', color: 'black' }}>
                {edu.degree} from {edu.institution}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {edu.dateRange}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {edu.description}
              </Typography>
              <Typography variant="body1" sx={{ fontWeight: 'bold', color: 'black' }}>
                {edu.mark}
              </Typography>
            </Box>
          ))}
        </Box>
      )}


      {skills && resumeData.skills?.length > 0 && (
        <Box mb={1}>
          <Typography variant="h6" sx={{ color: textColor, marginTop: '-10px' }}>Skills</Typography>
          <Divider sx={{ marginY: 0 }} />
          <Box display="flex" flexWrap="wrap">
            {resumeData.skills.map((skill, index) => (
              <Box
                key={index}
                sx={{
                  bgcolor: 'whitesmoke',
                  borderRadius: 1,
                  padding: .5,
                  margin: 0.5,
                  border: `1px solid ${textColor}`
                }}
              >
                <Typography variant="body2" sx={{ color: 'black' }}>
                  {skill || 'No Skill'}
                </Typography>
              </Box>
            ))}
          </Box>
        </Box>
      )}


      {projects && resumeData.projects?.length > 0 && (
        <Box mb={2}>
          <Typography variant="h6" sx={{ color: textColor, marginTop: '-12px' }}>Projects</Typography>
          <Divider sx={{ marginY: 0 }} />
          <List sx={{ margin: '-12px 0px' }}>
            {resumeData.projects.map((proj, index) => (
              <ListItem key={index} sx={{ paddingY: 1 }}>
                <Box flexGrow={1}>
                  <Typography variant="body1" sx={{ fontWeight: 'bold', color: 'black' }}>
                    {proj.title || 'No Title'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {proj.description || 'No Description'}
                  </Typography>
                  <Link href={proj.link || '#'} target="_blank" rel="noopener" color="primary">
                    View Project
                  </Link>
                </Box>
              </ListItem>
            ))}
          </List>
        </Box>
      )}


      {achievements && resumeData.achievements?.length > 0 && (
        <Box mb={2}>
          <Typography variant="h6" sx={{ color: textColor, marginTop: '-10px' }}>Achievements</Typography>
          <Divider sx={{ marginY: 0 }} />
          <List>
            {resumeData.achievements.map((ach, index) => (
              <ListItem key={index} sx={{ paddingY: 0 }}>
                <Box flexGrow={1}>
                  <Typography variant="body2" sx={{ color: 'black' }}>
                    {ach || 'No Achievement'}
                  </Typography>
                </Box>
              </ListItem>
            ))}
          </List>
        </Box>
      )}

      {pickerVisible && (
        <Box mt={2} className="color-picker">
          <ChromePicker
            color={bgColor}
            onChangeComplete={(color) => handleColorChange(color, 'background')}
            disableAlpha
          />
          <ChromePicker
            color={textColor}
            onChangeComplete={(color) => handleColorChange(color, 'text')}
            disableAlpha
          />
        </Box>
      )}

      {loader && (
        <Box mt={4} textAlign="center" className="no-print">
          <Button variant="contained" color="primary" onClick={handleDownloadPDF} style={{marginRight:"20px"}}>
            Download PDF
          </Button>
          <Button variant="contained" color="secondary" onClick={togglePicker}>
            {pickerVisible ? 'Hide Color Picker' : 'Show Color Picker'}
          </Button>
        </Box>
      )}
    </Paper>
  );
}

export default ResumePreview;