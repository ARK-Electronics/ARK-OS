/**
 * Blue Theme Preset
 * Professional blue color scheme
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
    black: 'rgba(0, 0, 0, 0.65)',
    blackBold: 'rgba(0, 0, 0, 1)',
    blackShadow: 'rgba(0, 0, 0, 0.1)',
    white: 'rgba(255, 255, 255, 1)',
    
    // Blue as primary color
    primary: 'rgba(25, 118, 210, 1)',             // Material Blue
    primaryHover: 'rgba(25, 118, 210, 0.8)',
    primaryShadow: 'rgba(25, 118, 210, 0.15)',
    
    secondary: 'rgba(66, 165, 245, 1)',           // Light Blue
    secondaryHover: 'rgba(66, 165, 245, 0.8)',
    
    success: 'rgba(76, 175, 80, 1)',              // Green
    warning: 'rgba(255, 152, 0, 1)',              // Orange
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
