import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Homepage from './components/Homepage';
import SignUpForm from './components/sign';
import JobList from './components/jobpostlist';
import EditJobPostForm from './components/editjobpost';
import JobPostForm from './components/jobpost';
import JobGetPage from './components/jobget';
import JobListingsPage from './components/jobgetinpage';
import LoginForm from './components/login';
import About from './components/aboutus';
import { RecemailProvider } from './context/recruiterauth';
import Mcq from './components/McqAi';
import ResourceSkills from './components/resourceskills';
import MapView from './components/Mapview';
import Resumeanalyser from './components/resumeanalyser';
import { Chatai } from './components/chatbox';
import Recruitorview from './components/recruitorview';
import PrivateRoute from './components/PrivateRoute';

function App() {
  return (
    <RecemailProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Homepage />} />
          <Route path="/adminlogin" element={<LoginForm />} />
          <Route path="/adminsignup" element={<SignUpForm />} />
          <Route path="/adminpostlist" element={<PrivateRoute><JobList /></PrivateRoute>} />
          <Route path="/adminpostedit/:id/" element={<PrivateRoute><EditJobPostForm /></PrivateRoute>} />
          <Route path="/adminaddpost" element={<PrivateRoute><JobPostForm /></PrivateRoute>} />
          <Route path="/userget" element={<JobGetPage />} />
          <Route path="/usergetlist/:id/" element={<JobListingsPage />} />
          <Route path="/aboutus" element={<About />} />
          <Route path="/Mcq/:id/" element={<Mcq />} />
          <Route path="/resource/:id/" element={<ResourceSkills />} />
          <Route path="/map" element={<MapView />} />
          <Route path="/resumeanylser" element={<Resumeanalyser />} />
          <Route path="/chatbox" element={<Chatai/>}/>
          <Route path="/recview/:id/" element={<Recruitorview />} />
        </Routes>
      </Router>
    </RecemailProvider>
  );
}

export default App;
