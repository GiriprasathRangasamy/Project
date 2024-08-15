import React from 'react';
import { ResumeProvider } from './context/ResumeContext';
import ResumePreview from './components/ResumePreview';
import Profile from './components/Profile';
import Experience from './components/Experience';

import Skills from './components/Skills';
import Projects from './components/Projects';
import Achievements from './components/Achievements';
import Contact from './components/Contact';
import Grid from '@mui/material/Grid';
import Container from '@mui/material/Container';
import Box from '@mui/material/Box';
import Education from './components/Education';
import './App.css'
import Header from './components/Header';

import {Route,Routes, BrowserRouter} from 'react-router-dom'
import { Home } from './components/Home';
function App() {
  return (
    <div className='resumeapp'>
    <ResumeProvider>
      <BrowserRouter>
      
              <Header/>         
<Routes>
    <Route path='/' element={<Home/>} ></Route> 
         </Routes>
     
  </BrowserRouter>
    </ResumeProvider>
    </div>
  );
}

export default App;
