import React, { useState } from 'react';
import axios from 'axios';
import { TextField, Button } from '@mui/material';
import UserNavbar from './usernavbar';
import UserFooter from './userfooter';
import { Height } from '@mui/icons-material';

const Resumeanalyser = () => {
  const [file, setFile] = useState(null);
  const [resumeAnalysis, setResumeAnalysis] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [field, setField] = useState('');

  const API_KEY = 'AIzaSyAbBZLvQKCvZYdEwvSrCPJvitb-iaIssSk'; // Replace with your Google API Key

  // Handle file upload
  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  // Function to upload the resume file
  const uploadFile = async () => {
    if (!file) {
      setError('Please select a file to upload.');
      return;
    }

    const fileSize = file.size; // Get file size

    // Prepare form data for file upload
    const formData = new FormData();
    formData.append('file', file);

    setLoading(true);
    setError(null);

    try {
      // Upload the file
      const uploadResponse = await axios.post(
        `https://generativelanguage.googleapis.com/upload/v1beta/files?key=${API_KEY}`,
        formData,
        {
          headers: {
            'X-Goog-Upload-Command': 'start, upload, finalize',
            'X-Goog-Upload-Header-Content-Length': fileSize,
            'X-Goog-Upload-Header-Content-Type': file.type,
            'Content-Type': 'multipart/form-data',
          },
        }
      );

      const cd = uploadResponse.data;
      // Retrieve the file URI
      const fileUri = cd.file.uri;
      console.log(cd);
      // Analyze the resume
      analyzeResume(fileUri);
    } catch (err) {
      setError('Error uploading the file: ' + err.message);
      setLoading(false);
    }
  };

  const analyzeResume = async (fileUri) => {
    try {
      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${API_KEY}`,
        {
          contents: [
            {
              role: 'user',
              parts: [
                {
                  fileData: {
                    fileUri: fileUri,
                    mimeType: file.type,
                  },
                },
                {
                  text: `Analyze my resume for field ${field} and provide a comprehensive assessment more important the header without comments and notations that includes a resume score out of 100, highlighting my strengths, areas of improvement, and skills to add. For strengths, identify key competencies and provide detailed descriptions of each, illustrating how they contribute to my career growth. For areas of improvement, list specific aspects that need enhancement, accompanied by actionable suggestions to make my resume more impactful. Identify skills I should add, categorized by field, and include a list of skills to improve in each field . Additionally, suggest other jobs field that align with my current skills and experience, explaining why these roles are suitable. Finally, provide a list of project ideas, detailing the tech stack used and a description of each project's purpose and objectives. Ensure that the analysis is comprehensive, informative, and tailored to my career goals. Give the my improved format of my resume in text. Here is my resume:.give text without star and double star`
                }
              ],
            },
          ],
          generationConfig: {
            temperature: 0.7,
            topK: 64,
            topP: 0.95,
            maxOutputTokens: 8192,
            responseMimeType: 'text/plain',
          },
        },
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );

      // Extract the response content
      const responseText = response.data.candidates[0].content.parts[0].text;
      console.log(responseText);

      // Set the analysis response
      setResumeAnalysis(responseText);
    } catch (err) {
      setError('Error analyzing the resume: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Function to clean text by removing leading and trailing stars and `undefined`
  const cleanText = (text) => {
    return text
      .replace(/\*\*/g, '') // Remove all double stars
      .replace(/\*/g, '')   // Remove all single stars
      .replace(/undefined/g, '') // Remove 'undefined'
      .trim();              // Remove extra whitespace
  };

  // Function to render the resume analysis in a formatted manner
  const renderResumeAnalysis = (analysisText) => {
    // Split the analysis text into lines
    const lines = analysisText.split('\n');

    // Function to create underlined bold text for header
    const renderBoldUnderlineHeader = (text) => (
      <h2 key={text} style={{ ...styles.sectionHeader, textDecoration: 'underline' }}>
        {cleanText(text)}
      </h2>
    );

    // Function to create bold text
    const renderBoldText = (text) => (
      <strong key={text} style={styles.boldText}>
        {cleanText(text)}
      </strong>
    );

    // Function to create bullet points
    const renderBulletPoint = (text) => (
      <li key={text} style={styles.bulletPoint}>{cleanText(text)}</li>
    );

    // Iterate through lines and create JSX elements
    const analysisContent = lines.map((line, index) => {
      // Check for section headers
      if (line.startsWith('**') && line.endsWith('**')) {
        return renderBoldUnderlineHeader(line.slice(2, -2));
      }

      // Check for bold text
      if (line.startsWith('**') && line.endsWith('**')) {
        return renderBoldText(line.slice(2, -2));
      }

      // Check for bullet points
      if (line.startsWith('* ')) {
        return renderBulletPoint(line.slice(2));
      }

      // Check for regular text
      if (line.trim() !== '') {
        return <p key={index} style={styles.text}>{cleanText(line)}</p>;
      }

      // Return null for empty lines
      return null;
    });

    return <div style={styles.analysisWrapper}>{analysisContent}</div>;
  };

  return (
    <div style={styles.pageWrapper}>
      <UserNavbar />
      <div style={styles.container}>
        <h1 style={styles.header}>Resume Analyzer</h1>
        <div style={styles.fileUploadContainer}>
          <label htmlFor="fileInput" style={styles.customFileInput}>
            {file ? file.name : 'Choose File'}
            <input
              id="fileInput"
              type="file"
              onChange={handleFileChange}
              style={{ display: 'none' }}
            />
          </label>
          <TextField
            label="Enter Your Role"
            value={field}
            onChange={(e) => setField(e.target.value)}
            style={styles.fieldInput}
          />
          <Button
            variant="contained"
            color="primary"
            onClick={uploadFile}
            style={styles.uploadButton}
            disabled={loading}
          >
            {loading ? 'Uploading...' : 'Upload and Analyze'}
          </Button>
        </div>
        {error && <p style={styles.error}>{error}</p>}
        {resumeAnalysis && (
          <div style={styles.analysisContainer}>
            <h2 style={styles.analysisHeader}>Resume Analysis</h2>
            {renderResumeAnalysis(resumeAnalysis)}
          </div>
        )}
      </div>
      <UserFooter />
    </div>
  );
};

// Simple styles for the app
const styles = {
  pageWrapper: {
    backgroundColor: '#f4f4f9',
    minHeight: '100vh',
  },
  container: {
    maxWidth: '800px',
    margin: 'auto',
    padding: '40px',
    fontFamily: 'Roboto, sans-serif',
    lineHeight: '1.6',
    color: '#333',
    backgroundColor: '#fff',
    borderRadius: '8px',
    boxShadow: '0 4px 8px rgba(0,0,0,0.1)',
  },
  header: {
    textAlign: 'center',
    color: '#007bff',
    marginBottom: '20px',
    fontSize: '24px',
  },
  fileUploadContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '20px',
  },
  customFileInput: {
    display: 'inline-block',
    padding: '10px 20px',
    backgroundColor: 'black',
    color: '#fff',
    borderRadius: '4px',
    cursor: 'pointer',
    width: '30%',
    textAlign: 'center',
    transition: 'background-color 0.3s',
    border: '1px solid transparent',
  },
  fileInput: {
    display: 'none',
  },
  fieldInput: {
    width: '60%',
  },
  uploadButton: {
   width: '30%',
    Height:"35px",
    padding: '12px',
    borderRadius: '4px',
    backgroundColor:"red"
  },
  error: {
    color: '#dc3545',
    textAlign: 'center',
    marginTop: '10px',
  },
  analysisContainer: {
    marginTop: '30px',
    backgroundColor: '#f8f9fa',
    padding: '20px',
    borderRadius: '8px',
    boxShadow: '0 4px 8px rgba(0,0,0,0.1)',
  },
  analysisHeader: {
    color: '#333',
    marginBottom: '15px',
    fontSize: '20px',
  },
  analysisWrapper: {
    marginTop: '20px',
  },
  sectionHeader: {
    fontSize: '18px',
    fontWeight: 'bold',
    marginTop: '20px',
    marginBottom: '10px',
    color: '#444',
  },
  boldText: {
    fontWeight: 'bold',
    color: '#333',
  },
  text: {
    marginBottom: '10px',
    color: '#666',
  },
  bulletPoint: {
    color: '#555',
    listStyleType: 'disc', // Add this to show bullet points
    paddingLeft: '20px', // Ensure proper indentation for bullet points
  },
};

export default Resumeanalyser;
