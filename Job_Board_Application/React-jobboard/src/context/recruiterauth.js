import React, { createContext, useState, useContext, useEffect } from 'react';

// Create context
const RecemailContext = createContext();

// Context Provider component
export const RecemailProvider = ({ children }) => {
    const [recemail, setRecemail] = useState(() => localStorage.getItem('recemail') || null);

    useEffect(() => {
        if (recemail) {
            localStorage.setItem('recemail', recemail);
        }
    }, [recemail]);

    return (
        <RecemailContext.Provider value={{ recemail, setRecemail }}>
            {children}
        </RecemailContext.Provider>
    );
};

// Custom hook to use the RecemailContext
export const useRecemail = () => useContext(RecemailContext);