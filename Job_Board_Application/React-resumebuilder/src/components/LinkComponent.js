import React from 'react';
import Link from '@mui/material/Link';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';

function LinkComponent({ href, text }) {
  return (
    <Box marginY={1} sx={{background:'white'}}>
      <Typography variant="body1">
        <Link href={href} target="_blank" rel="noopener" color="primary">
          {text}
        </Link>
      </Typography>
    </Box>
  );
}

export default LinkComponent;
