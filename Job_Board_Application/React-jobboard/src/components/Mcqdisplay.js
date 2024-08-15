// src/MCQComponent.js

import React, { useState } from 'react';
import './Mcq.css';
import { Button } from '@mui/material';
import { useNavigate, useParams } from 'react-router-dom';

const MCQComponent = ({ mcqs }) => {
  const {id}=useParams();
  const navigate=useNavigate();
  const [userAnswers, setUserAnswers] = useState({});
  const [showScore, setShowScore] = useState(false); 
  const [scores, setScores] = useState({}); 

 
  const handleAnswerSelect = (skill, questionIndex, answer) => {
    setUserAnswers((prevAnswers) => ({
      ...prevAnswers,
      [skill]: {
        ...prevAnswers[skill],
        [questionIndex]: answer,
      },
    }));
  };

 
  const calculateScore = () => {
    const calculatedScores = {};

    Object.keys(mcqs).forEach((skill) => {
      if (!skill.includes('_resource')) {
        const correctAnswers = mcqs[skill].filter(
          (mcq, index) => userAnswers[skill]?.[index] === mcq.answer
        ).length;

        calculatedScores[skill] = correctAnswers;
      }
    });

    setScores(calculatedScores);
    setShowScore(true);
  };

  return (
    <div className="mcq-container">
      {Object.keys(mcqs).map((skill) => {
        if (!skill.includes('_resource')) {
          return (
            <div key={skill} className="skill-section">
              <h2>{skill.toUpperCase()}</h2>
              {mcqs[skill].map((mcq, index) => (
                <div key={index} className="mcq">
                  <p>
                    {index + 1}. {mcq.question}
                  </p>
                  <div className="options">
                    {mcq.options.map((option, idx) => (
                      <label key={idx}>
                        <input
                          type="radio"
                          name={`answer-${skill}-${index}`}
                          value={option}
                          checked={userAnswers[skill]?.[index] === option}
                          onChange={() =>
                            handleAnswerSelect(skill, index, option)
                          }
                          disabled={showScore}
                        />
                        {option}
                      </label>
                    ))}
                  </div>

                  {showScore && (
                    <div>
                      <p>
                        Correct Answer:{' '}
                        <span className="correct-answer">{mcq.answer}</span>
                      </p>
                      <p>
                        Your Answer:{' '}
                        <span
                          className={
                            userAnswers[skill]?.[index] === mcq.answer
                              ? 'correct'
                              : 'incorrect'
                          }
                        >
                          {userAnswers[skill]?.[index] || 'Not Answered'}
                        </span>
                      </p>
                    </div>
                  )}
                </div>
              ))}

            </div>
          );
        }
        return null;
      })}
      <button
        onClick={calculateScore}
        className="calculate-score-button"
        disabled={showScore}
      >
        {showScore ? 'Score Calculated' : 'Calculate Score'}
      </button>
      {showScore && (
        <div className="scores">
          <h3>Scores:</h3>
          {Object.keys(scores).map((skill) => (
            <p key={skill}>
              {skill.toUpperCase()}: {scores[skill]} / {mcqs[skill].length}
            </p>
          ))}
        </div>
      )}
      {showScore &&  <Button href={`/resource/${id}`} sx={{border:"solid 1px grey", backgroundColor:"#61dafb",color:'black',fontSize:"1.2em"}}>Get Best Resource</Button>}
    </div>
  );
};

export default MCQComponent;
