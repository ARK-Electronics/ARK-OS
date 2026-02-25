/**
 * Dark Mode Theme Preset
 * Copy the contents of this file to theme.config.js to apply dark mode
 */

export default {
  branding: {
    name: 'ARK Electronics',
    logoPath: 'logo.png',
    logoWidth: 120,
    logoHeight: 'auto',
    faviconPath: 'favicon.ico'
  },

  colors: {
    // Dark mode: inverted colors
    black: 'rgba(255, 255, 255, 0.87)',           // Light text
    blackBold: 'rgba(255, 255, 255, 1)',          // White text
    blackShadow: 'rgba(0, 0, 0, 0.5)',            // Darker shadows
    white: 'rgba(18, 18, 18, 1)',                 // Dark background
    
    // Keep brand colors or adjust for dark mode
    primary: 'rgba(0, 220, 60, 1)',               // Brighter green
    primaryHover: 'rgba(0, 220, 60, 0.8)',
    primaryShadow: 'rgba(0, 220, 60, 0.2)',
    
    secondary: 'rgba(52, 152, 219, 1)',
    secondaryHover: 'rgba(52, 152, 219, 0.8)',
    
    success: 'rgba(0, 220, 60, 1)',
    warning: 'rgba(255, 160, 0, 1)',
    error: 'rgba(255, 87, 74, 1)',
    errorHover: 'rgba(255, 87, 74, 0.8)',
    
    lightGrey: 'rgba(30, 30, 30, 1)',             // Dark grey
    grey: 'rgba(170, 170, 170, 1)'                // Light grey
  },

  typography: {
    fontFamily: "'Roboto', sans-serif",
    fontImports: [
      '@import url("https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap");'
    ]
  },

  layout: {
    sidebarInitialWidth: 152,
    sidebarPadding: '0px 20px',
    contentPaddingHorizontal: '4vh',
    linkPadding: '10px 15px',
    linkMargin: '8px 0',
    linkBorderRadius: '5px',
    transitionSpeed: '0.1s',
    hoverTranslateX: '5px'
  },

  externalLinks: {
    showFlightReview: true,
    customLinks: []
  },

  customCSS: `
    /* Additional dark mode adjustments */
    .sidebar {
      box-shadow: 2px 0 20px rgba(0, 0, 0, 0.8) !important;
    }
  `
};
