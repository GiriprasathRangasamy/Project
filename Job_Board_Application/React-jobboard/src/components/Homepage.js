import { Button } from "@mui/material";
import KeyboardDoubleArrowRightIcon from '@mui/icons-material/KeyboardDoubleArrowRight';
import "./Homepage.css"
import img from '../components/images/postjob.png'
import Navbar from "./Navbar";
import img1 from '../components/images/searchjob.png'
import Footer from "./footer";
function Homepage()
{
    return(
        
        <div id='home'>
            <Navbar/>
            <div id="heading">
            
            <h1>Welcome to Job Board !</h1>
            <p>
            Discover a wide range of opportunities from top companies.</p>
            <p> Whether you're looking for a career change or your first job, we've got you covered.</p>
            <p>Explore thousands of listings and find your dream job today.</p>
            <p>Your future starts here – take the first step now!</p>
            </div>
            <div id="items">
            <div id="postjob">
                <img src={img} alt="image" className="img"></img>
                <h4>Do you want to Hire?</h4>
                <p>Then post the Job ...</p>
                <Button variant="contained" sx={{backgroundColor:"#f7d48d"}} href="/adminlogin" endIcon={<KeyboardDoubleArrowRightIcon />}>Post Job </Button>
            </div>
            <div id="getjob">
                <img src={img1} alt="image" className="img" ></img>
                <h4>Do you Look for Job?</h4>
                <p>Then Search Job ...</p>
                <Button variant="contained" sx={{backgroundColor:"#f7bc99"}} href='/userget' endIcon={<KeyboardDoubleArrowRightIcon />}>Search Job</Button>
            </div>
            </div>
           <Footer/>
        </div>
    );
};
export default Homepage