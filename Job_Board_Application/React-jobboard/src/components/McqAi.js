import React, { useState, useEffect } from 'react';
import axios from 'axios';
import MCQComponent from './Mcqdisplay';
import './Mcq.css';
import { useParams } from 'react-router-dom';
import UserNavbar from './usernavbar';
import UserFooter from './userfooter';
import { TextField, Button } from '@mui/material'; // Import TextField and Button from Material UI

const Mcq = () => {
  const { id } = useParams(); // Get the job ID from the URL
  const [mcqs, setMcqs] = useState(null); // Store MCQs data
  const [loading, setLoading] = useState(false); // Handle loading state
  const [job, setJob] = useState(null); // Store job details
  const [error, setError] = useState(null); // Handle errors
  const [viewsa, setViewsa] = useState(false); // Handle view state
  const [skillset, setSkillset] = useState(""); // Store user-entered skill set

  const API_KEY = 'AIzaSyAbBZLvQKCvZYdEwvSrCPJvitb-iaIssSk'; 
  const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${API_KEY}`; 

  useEffect(() => {
    // Fetch job details only if id is not 0
    if (id !== '0') {
      const fetchJobDetails = async () => {
        try {
          const response = await fetch(`http://localhost:8080/user/jobdetail/${id}`);
          if (!response.ok) {
            throw new Error('Failed to fetch job data');
          }
          const jobData = await response.json();
          setJob(jobData); 
        } catch (error) {
          setError(error.message); 
        }
      };

      fetchJobDetails(); 
    }
  }, [id]);

  const fetchMCQs = async () => {
    setLoading(true); 
    setViewsa(true);
    setError(null); 

    // Check if skillset or job data is available
    if (!skillset && !job) {
      setError('Please enter skills or wait for job data to load.');
      setLoading(false);
      return;
    }

    const skills = skillset || (job && job.skills.join(', ')); 
    console.log("Using skills:", skills);

    try {
      const response = await axios.post(API_URL, {
        contents: [
          {
            role: 'user',
            parts: [
              {
                text: `Generate 5 MCQs for each skill in ${skills}, along with the answers. Provide in format of skills and array of question and array of options and correct answer for that question.`,
              },
            ],
          },
        ],
        generationConfig: {
          temperature: 1,
          topK: 64,
          topP: 0.95,
          maxOutputTokens: 8192,
          responseMimeType: 'application/json',
        },
        safetySettings: [
          {
            category: 'HARM_CATEGORY_HARASSMENT',
            threshold: 'BLOCK_MEDIUM_AND_ABOVE',
          },
          {
            category: 'HARM_CATEGORY_HATE_SPEECH',
            threshold: 'BLOCK_MEDIUM_AND_ABOVE',
          },
          {
            category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT',
            threshold: 'BLOCK_MEDIUM_AND_ABOVE',
          },
          {
            category: 'HARM_CATEGORY_DANGEROUS_CONTENT',
            threshold: 'BLOCK_MEDIUM_AND_ABOVE',
          },
        ],
      });

      const content = JSON.parse(response.data.candidates[0].content.parts[0].text);
      console.log('API Response:', content);

      setMcqs(Array.isArray(content) ? [] : content);
    } catch (error) {
      console.error('Error fetching MCQs:', error);
      setError('An error occurred while fetching MCQs.');
    } finally {
      setLoading(false); 
    }
  };

  return (
    <>
      <UserNavbar/>
      <div className="App" style={{ height: "100%", minHeight: "80vh", alignContent: "center" }}>
        <h1>MCQ Knowledge Check</h1>
        
        {id === '0' && (
          <div className="skill-input">
            <TextField
              label="Enter Skills (comma separated)"
              variant="outlined"
              fullWidth
              value={skillset}
              onChange={(e) => setSkillset(e.target.value)}
              style={{ marginBottom: '1em', width: '50%' }} // Adjust width as needed
            />
          </div>
        )}
        
        <Button
          variant="contained"
          color="primary"
          onClick={fetchMCQs}
          disabled={loading || (!job && id !== '0')}
          style={{ marginBottom: '1em' }}
        >
          {loading ? 'Loading...' : 'Check Knowledge'}
        </Button>

        {viewsa && (
          <main>
            {loading ? (
              <h3>Hold on for a moment...</h3>
            ) : (
              <>
                {error && <p className="error">{error}</p>} 
                {mcqs && <MCQComponent mcqs={mcqs} />}
              </>
            )}
          </main>
        )}
      </div>
      <UserFooter/>
    </>
  );
};

export default Mcq;
