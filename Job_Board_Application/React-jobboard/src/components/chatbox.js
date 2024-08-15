import React, { useState } from 'react';
import axios from 'axios';
import { Box, TextField, Button, Typography, Paper, Container } from '@mui/material';
import { styled } from '@mui/system';
import UserNavbar from './usernavbar';
import UserFooter from './userfooter';

// Styled components with enhanced design
const ChatContainer = styled(Container)(({ theme }) => ({
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  padding: theme.spacing(4),
  background: 'linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%)',
  borderRadius: '16px',
  boxShadow: '0 8px 16px rgba(0, 0, 0, 0.2)',
  height:'100%',
  maxWidth: '600px',
  width: '100%',
}));

const ChatInput = styled(TextField)(({ theme }) => ({
  marginBottom: theme.spacing(2),
  width: '100%',
  '& .MuiInputBase-root': {
    fontSize: '18px',
    padding: theme.spacing(1.5),
  },
  '& .MuiOutlinedInput-root': {
    borderRadius: '12px',
    backgroundColor: '#ffffff',
    '& fieldset': {
      borderColor: '#1976d2',
    },
    '&:hover fieldset': {
      borderColor: '#1565c0',
    },
    '&.Mui-focused fieldset': {
      borderColor: '#1976d2',
    },
  },
}));

const ChatButton = styled(Button)(({ theme }) => ({
  margin: theme.spacing(2, 0),
  padding: theme.spacing(1.5, 4),
  fontSize: '16px',
  borderRadius: '30px',
  background: 'linear-gradient(45deg, #ff6f61 30%, #ff3f3f 90%)',
  color: 'white',
  boxShadow: '0 4px 8px rgba(0, 0, 0, 0.3)',
  '&:hover': {
    background: 'linear-gradient(45deg, #ff3f3f 30%, #ff6f61 90%)',
  },
}));

const ChatResponse = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(2),
  marginTop: theme.spacing(2),
  backgroundColor: '#e3f2fd',
  borderRadius: '12px',
  boxShadow: '0 6px 12px rgba(0, 0, 0, 0.2)',
  width: '100%',
  textAlign: 'left',
  overflowWrap: 'break-word',
}));

const boldifyText = (text) => {
  return text
    .replace(/\*(.*?)\*/g, '<b>$1</b>')
    .replace(/(?:\r\n|\r|\n)/g, '<br />')
};

export const Chatai = () => {
  const [question, setQuestions] = useState("");
  const [answer, setAnswers] = useState("");

  async function generateAnswer() {
    try {
      const response = await axios({
        url: "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=AIzaSyAbBZLvQKCvZYdEwvSrCPJvitb-iaIssSk",
        method: "post",
        data: { "contents": [{ "parts": [{ "text": `${question} in string chat without comments` }] }] },
      });
      console.log(response.data);
      setAnswers(boldifyText(response.data.candidates[0].content.parts[0].text));
    } catch (error) {
      console.error("Error generating answer:", error);
    }
  }

  return (
    <div>
      <UserNavbar/>
    <Box className='body1' sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', backgroundColor: '#f0f4f8' }}>
      <ChatContainer>
        <Typography variant="h4" gutterBottom color="#1976d2">Chat Box</Typography>
        <ChatInput
          multiline
          rows={6}
          variant="outlined"
          value={question}
          onChange={(e) => setQuestions(e.target.value)}
          placeholder="Type your question here..."
        />
        <ChatButton variant="contained" onClick={generateAnswer}>Generate Answer</ChatButton>
        {answer && (
          <ChatResponse elevation={3}>
            <div dangerouslySetInnerHTML={{ __html: answer }} />
          </ChatResponse>
        )}
      </ChatContainer>
    </Box>
    <UserFooter/>
    </div>
  );
};