import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './RSkills.css';
import { useParams } from 'react-router-dom';
import UserNavbar from './usernavbar';
import UserFooter from './userfooter';
import { TextField, Button } from '@mui/material'; // Import Button from Material UI

const ResourceSkills = () => {
  const [job, setJob] = useState(null); 
  const [resources, setResources] = useState(null); 
  const [loading, setLoading] = useState(false); 
  const [txtshow, setTxtshow] = useState(true); 
  const [error, setError] = useState(null); 
  const { id } = useParams();
  const [show, setShow] = useState(false);
  const [skillset, setSkillset] = useState(""); // State for custom skill input

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

  const fetchResources = async () => {
    // Check if skillset or job data is available
    if (!skillset && !job) {
      setError('Please enter skills or wait for job data to load.');
      return;
    }

    const skills = skillset || (job && job.skills.join(', ')); 
    setLoading(true);
    setError(null);
    setTxtshow(false);

    try {
      const response = await axios.post(API_URL, {
        contents: [
          {
            role: 'user',
            parts: [
              {
                text: `For the skills: ${skills}, provide a list of best online resources more than 5, including links to roadmap, articles, courses, coding practice, and tutorials that can help in further learning and practice. Give it in form of skill and array of type, link, and title.`,
              },
            ],
          },
          {
            role: 'user',
            parts: [
              {
                text: 'INSERT_INPUT_HERE',
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

      console.log('API Response:', response.data);

      const content = JSON.parse(response.data.candidates[0].content.parts[0].text);
      console.log(content);
      setShow(true);
      
      setResources(content); 
    } catch (error) {
      console.error('Error fetching resources:', error);
      setError('An error occurred while fetching resources.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <UserNavbar />
      <div className="App" style={{ minHeight: "80vh", height: "100%", alignContent: "center" }}>
        {txtshow && <>
          <h1>Do You Want To UpSkill For the Job?</h1>
          <h1>Then Get Resource to Learn</h1>
        </>}
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
          onClick={fetchResources}
          disabled={loading || (!job && id !== '0')}
          style={{ marginBottom: '1em' }}
        >
          {loading ? 'Loading...' : 'Get Resources'}
        </Button>
        {show && (
          <main>
            {error && <p className="error">{error}</p>}
            {resources && (
              <div className="resources">
                {Object.keys(resources).map((skill) => (
                  <div key={skill} className="resource-section">
                    <h2><u>{skill.toUpperCase()}</u></h2>
                    <ul>
                      {resources[skill].map((resource, index) => (
                        <li key={index} style={{fontSize:"1.3em", gap:"10px"}}>
                          <h4>{resource.type}:</h4>
                          <a href={resource.link} target="_blank" rel="noopener noreferrer">
                            {resource.title}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </main>
        )}
      </div>
      <UserFooter />
    </>
  );
};

export default ResourceSkills;
