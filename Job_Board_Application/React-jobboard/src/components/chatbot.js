

import React, { useState } from 'react';
import axios from 'axios';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCommentDots, faPaperPlane, faTimes } from '@fortawesome/free-solid-svg-icons';
import './ChatBot.css'; 

const API_KEY = 'AIzaSyAbBZLvQKCvZYdEwvSrCPJvitb-iaIssSk';

const ChatBot = () => {
  const [isOpen, setIsOpen] = useState(false); 
  const [messages, setMessages] = useState([]); 
  const [userMessage, setUserMessage] = useState(''); 

 
  const toggleChat = () => {
    setIsOpen(!isOpen);
  };


  const handleSendMessage = async () => {
    if (!userMessage.trim()) return;


    const newMessage = { sender: 'user', text: userMessage };
    setMessages([...messages, newMessage]);
    setUserMessage('');

    try {
      const response = await axios({
        url: "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=AIzaSyAbBZLvQKCvZYdEwvSrCPJvitb-iaIssSk",
        method: "post",
        data: { "contents": [{ "parts": [{ "text": `${userMessage} in string chat without notation and comments your are worker for my jobboard application
          as a help assistent you have to reply for doubts about jobboard application` }] }] },});
     
      const Response = (await response.data.candidates[0].content.parts[0].text);
      const  geminiResponse=Response
console.log(geminiResponse)
    
      setMessages((prevMessages) => [
        ...prevMessages,
        { sender: 'bot', text: geminiResponse }
      ]);
    } catch (error) {
      console.error('Error getting response from Gemini API:', error);
      setMessages((prevMessages) => [
        ...prevMessages,
        { sender: 'bot', text: 'Sorry, something went wrong. Please try again later.' },
      ]);
    }
  };


  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSendMessage();
    }
  };

  return (
    <div className={`chatbot-container ${isOpen ? 'open' : ''}`}>
      <div className="chatbot-icon" onClick={toggleChat}>
        {isOpen ? <FontAwesomeIcon icon={faTimes}/> : <FontAwesomeIcon icon={faCommentDots} />}
      </div>

      {isOpen && (
        <div className="chatbox">
          <div className="chatbox-header">
            <h3>Get TO Know !</h3>
          </div>
          <div className="chatbox-body">
            {messages.map((message, index) => (
              <div key={index} className={`chat-message ${message.sender}`}>
                <div className="message-text">{message.text}</div>
              </div>
            ))}
          </div>
          <div className="chatbox-footer">
            <input
              type="text"
              placeholder="Type a message..."
              value={userMessage}
              onChange={(e) => setUserMessage(e.target.value)}
              onKeyPress={handleKeyPress}
            />
            <button onClick={handleSendMessage}>
              <FontAwesomeIcon icon={faPaperPlane} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ChatBot;
