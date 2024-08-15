import './Navbar.css'
import img from '../components/images/img3.jpeg'
import { Button } from '@mui/material';
import KeyboardDoubleArrowRightIcon from '@mui/icons-material/KeyboardDoubleArrowRight';
function Navbar()
{
    return(
        <div id='nav'>
            <div id='icon'>
                <img src={img} id='img1'></img>
                <h1 style={{fontFamily:'unset',paddingLeft:"20px"}}>SkillMatch</h1>
            </div>
            <div className='link1'>
                <h2><a href='/'>Home</a></h2>
                <h2><a href='/aboutus'>About Us</a></h2>
            </div>
            <div className='user'>
            <Button variant="contained" sx={{backgroundColor:"#f7701b"}} href="/adminlogin" endIcon={<KeyboardDoubleArrowRightIcon />}>Post Job </Button>
            <Button variant="contained" sx={{backgroundColor:"#fc1287"}} href='/userget' endIcon={<KeyboardDoubleArrowRightIcon />}>Search Job</Button>
            </div>
        </div>
    );
};
export default Navbar