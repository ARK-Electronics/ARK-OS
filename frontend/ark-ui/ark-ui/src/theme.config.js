/**
 * ARK-UI Active Theme Configuration
 * 
 * Edit this file to customize the UI appearance.
 * See theme.template.js for documentation of all available options.
 * See themes/ folder for preset themes you can copy from.
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
    text: 'rgba(0, 0, 0, 0.65)',
    textBold: 'rgba(0, 0, 0, 1)',
    shadow: 'rgba(0, 0, 0, 0.1)',
    background: 'rgba(255, 255, 255, 1)',
    
    // ARK Green - Primary brand color
    primary: 'rgba(0, 187, 49, 1)',
    primaryHover: 'rgba(0, 187, 49, 0.65)',
    primaryShadow: 'rgba(0, 187, 49, 0.1)',
    
    // Blue - Secondary color
    secondary: 'rgba(52, 152, 219, 1)',
    secondaryHover: 'rgba(52, 152, 219, 0.8)',
    
    // Status colors
    success: 'rgba(0, 187, 49, 1)',
    warning: 'rgba(255, 140, 0, 1)',
    error: 'rgba(244, 67, 54, 1)',
    errorHover: 'rgba(244, 67, 54, 0.65)',
    
    lightGrey: 'rgba(248, 249, 250, 1)',
    grey: 'rgba(102, 102, 102, 1)'
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

  customCSS: ``
};
