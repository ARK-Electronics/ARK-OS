/**
 * ARK-UI Active Theme Configuration
 * 
 * Edit this file to customize the UI appearance.
 * See theme.template.js for documentation of all available options.
 * See themes/ folder for preset themes you can copy from.
 */

export default {
  branding: {
    name: 'Pat',
    logoPath: 'logo.png',
    logoWidth: 120,
    logoHeight: 'auto',
    faviconPath: 'radio.ico'
  },

  colors: {
    text: 'rgba(167, 145, 145, 0.65)',
    textBold: 'rgba(0, 0, 0, 1)',
    shadow: 'rgba(0, 0, 0, 0.1)',
    background: 'rgba(243, 240, 240, 1)',
    
    // Blue as primary color
    primary: 'rgba(7, 115, 223, 1)',             // Material Blue
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
      customLinks: [
    {
      name: 'GitHub',
      url: 'https://github.com/ARK-Electronics',
      icon: 'fab fa-github'  // Optional, defaults to external link icon
    },
    {
      name: 'Documentation',
      url: 'https://docs.arkelectron.com'
    }
  ]

  },

  customCSS: ``
};
