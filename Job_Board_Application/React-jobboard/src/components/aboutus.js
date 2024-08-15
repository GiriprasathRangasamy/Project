// src/components/AboutUs.js
import React from 'react';
import './About.css';

import Footer from './footer';
import Navbar from './Navbar';

const About = () => {
  return (
    <div>
        <Navbar/>
    <div className="about-us">
      <div className="about-header">
        <h1>About Us</h1>
        <p>Connecting talent with opportunity</p>
      </div>
      <div className="about-content">
        <section className="who-we-are">
          <h2>Who We Are</h2>
          <hr/>
          <p>
            We are a dedicated team of professionals committed to bridging the gap between
            employers and job seekers. Our platform provides a seamless experience for posting
            and finding jobs, catering to a wide range of industries and skill levels.
          </p>
        </section>
        <section className="mission">
          <h2>Our Mission</h2>
          <hr/>
          <p>
            Our mission is to empower job seekers and employers by providing a user-friendly,
            efficient, and effective platform for job posting and job searching. We strive to
            create a dynamic ecosystem where talent meets opportunity.
          </p>
        </section>
        <section className="vision">
          <h2>Our Vision</h2>
          <hr/>
          <p>
            We envision a world where every individual has access to meaningful employment
            opportunities and every employer can find the right talent to drive their business
            forward.
          </p>
        </section>
        <section className="team">
          <h2>Our Team</h2>
          <hr/>
          <p>
            Our team is composed of experienced professionals from various fields, including
            technology, human resources, and customer service. We are passionate about helping
            people achieve their career goals and helping businesses succeed.
          </p>
        </section>
        <section className="history">
          <h2>Our History</h2>
          <hr/>
          <p>
            Founded in 2024, our platform has grown rapidly to become a trusted resource for
            both job seekers and employers. We have continuously evolved to meet the changing
            needs of the job market, always prioritizing innovation and user satisfaction.
          </p>
        </section>
      </div>
    </div>
      <Footer/>
    </div>
  );
}

export default About;