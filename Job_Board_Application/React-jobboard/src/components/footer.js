import React from 'react';
import './footer.css';

const Footer = () => {
  return (
    <footer className="footer">
      <div className="footer-container">
        <div className="footer-section">
          <h4>About Us</h4>
          <p>
            We are a leading job board connecting talented individuals with top companies.
            Our mission is to empower job seekers with the tools they need to find their dream jobs.
          </p>
        </div>
        <div className="footer-section">
          <h4>Quick Links</h4>
          <ul className="footer-list">
            <li><a className="footer-link" href="/">Home</a></li>
            <li><a className="footer-link" href="/aboutus">About Us</a></li>
            
          </ul>
        </div>
        <div className="footer-section">
          <h4>Contact Us</h4>
          <p>Email: support@jobboard.com</p>
          <p>Phone: 76567-8901</p>
        </div>
      </div>
      <div className="footer-bottom">
        <p>&copy; {new Date().getFullYear()} SkillMatch. All Rights Reserved.</p>
      </div>
    </footer>
  );
};

export default Footer;
