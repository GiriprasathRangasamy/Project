import React, { createContext, useState, useContext } from 'react';

// Create the context
const ResumeContext = createContext();

// Custom hook to use the context
export const useResume = () => useContext(ResumeContext);

// Context provider component
export const ResumeProvider = ({ children }) => {
  // State for resume data
  const [loader,setLoader]=useState(true);
  const [resumeData, setResumeData] = useState({
    profile: {
      image: '',
      name: '',
      email: '',
      phone: '',
      github: '',
      linkedin: '',
      address: '',
    },
    professionalSummary: '',
    experience: [],
    education: [],
    skills: [],
    projects: [],
    achievements: [],
  });

  // State for section visibility
  const [sectionsVisible, setSectionsVisible] = useState({
    professionalSummary: true,
    experience: true,
    education: true,
    skills: true,
    projects: true,
    achievements: true,
  });

  // Update profile information
  const updateProfile = (profile) => {
    setResumeData((prevData) => ({
      ...prevData,
      profile: { ...prevData.profile, ...profile },
    }));
  };

  // Add methods for different sections
  const addExperience = (exp) => setResumeData((prevData) => ({
    ...prevData,
    experience: [...prevData.experience, exp],
  }));

  const addEducation = (edu) => setResumeData((prevData) => ({
    ...prevData,
    education: [...prevData.education, edu],
  }));

  const addSkill = (skill) => setResumeData((prevData) => ({
    ...prevData,
    skills: [...prevData.skills, skill],
  }));

  const addProject = (project) => setResumeData((prevData) => ({
    ...prevData,
    projects: [...prevData.projects, project],
  }));

  const addAchievement = (achievement) => setResumeData((prevData) => ({
    ...prevData,
    achievements: [...prevData.achievements, achievement],
  }));

  // Remove methods for different sections
  const removeExperience = (index) => setResumeData((prevData) => ({
    ...prevData,
    experience: prevData.experience.filter((_, i) => i !== index),
  }));

  const removeEducation = (index) => setResumeData((prevData) => ({
    ...prevData,
    education: prevData.education.filter((_, i) => i !== index),
  }));

  const removeSkill = (index) => setResumeData((prevData) => ({
    ...prevData,
    skills: prevData.skills.filter((_, i) => i !== index),
  }));

  const removeProject = (index) => setResumeData((prevData) => ({
    ...prevData,
    projects: prevData.projects.filter((_, i) => i !== index),
  }));

  const removeAchievement = (index) => setResumeData((prevData) => ({
    ...prevData,
    achievements: prevData.achievements.filter((_, i) => i !== index),
  }));

  // Hide or show sections
  const toggleSectionVisibility = (section, isVisible) => {
    setSectionsVisible((prevVisible) => ({
      ...prevVisible,
      [section]: isVisible,
    }));
  };

  return (
    <ResumeContext.Provider value={{
      resumeData,
      sectionsVisible,
      updateProfile,
      addExperience,
      addEducation,
      addSkill,
      addProject,
      addAchievement,
      removeExperience,
      removeEducation,
      removeSkill,
      removeProject,
      removeAchievement,
      hideSection: (section) => toggleSectionVisibility(section, false),
      showSection: (section) => toggleSectionVisibility(section, true),
      loader,setLoader
    }}>
      {children}
    </ResumeContext.Provider>
  );
};
