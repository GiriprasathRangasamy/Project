import React from 'react'; // Import React
import './usernavbar.css'; // Import CSS
import img from '../components/images/img3.jpeg'; // Import image
import { Divider } from '@mui/material'; // Import Divider from MUI
import { useLocation, Link } from 'react-router-dom'; // Import necessary components from React Router
import UserFooter from './userfooter'; // Import Footer

function UserNavbar() {
  const location = useLocation(); // Hook to get the current location

  // Function to determine if the link is active based on the current path
  const isActiveLink = (path) => location.pathname === path;

  return (
    <div>
      <div id="nav1">
        {/* Navbar Icon Section */}
        <Link to="/" style={{ textDecoration: 'none', color: 'black' }}>
          <div id="icon">
            <img src={img} id="img1" alt="Logo" />
            <h1 style={{ fontFamily: 'unset' }}>SkillMatch</h1>
            <Divider orientation="vertical" variant="middle" flexItem />
          </div>
        </Link>

        {/* Links Section */}
        <div className="link">
          <h4>
            <Link
              to="/userget"
              className={isActiveLink('/userget') ? 'active-link' : ''}
            >
              Home
            </Link>
          </h4>
          <h4>
            <Link to="/map" className={isActiveLink('/map') ? 'active-link' : ''}>
              By Map
            </Link>
          </h4>
          <h4>
            <Link
              to="/Mcq/0"
              className={isActiveLink('/Mcq/0') ? 'active-link' : ''}
            >
              Check Knowledge
            </Link>
          </h4>
          <h4>
            <Link
              to="/resource/0"
              className={isActiveLink('/resource/0') ? 'active-link' : ''}
            >
              Get Resource
            </Link>
          </h4>
          <h4>
            <a
              href="http://localhost:3001/"
              className={isActiveLink('http://localhost:3001/') ? 'active-link' : ''}
            >
              Build Resume
            </a>
          </h4>
          <h4>
            <Link
              to="/resumeanylser"
              className={isActiveLink('/resumeanylser') ? 'active-link' : ''}
            >
              Resume Analyser
            </Link>
          </h4>
          <h4>
            <Link
              to="/chatbox"
              className={isActiveLink('/chatbox') ? 'active-link' : ''}
            >
              Chat Box
            </Link>
          </h4>
        </div>
      </div>

    </div>
  );
}

export default UserNavbar;
