/**
 * ARK-UI Theme Configuration Template
 * 
 * This file defines the visual appearance of the ARK-UI.
 * Copy this to 'theme.config.js' and customize the values.
 * 
 * Color formats: Use rgba(r, g, b, a) format where:
 *   r, g, b = 0-255
 *   a = 0-1 (opacity)
 * 
 * DARK MODE: To create a dark theme, invert the semantic color meanings:
 *   - text: light colors (for dark backgrounds)
 *   - background: dark colors
 *   Example: text: 'rgba(255, 255, 255, 0.87)', background: 'rgba(18, 18, 18, 1)'
 */

export default {
  // Brand Identity
  branding: {
    // Company/Product name - shown in UI header AND browser tab title
    name: 'ARK Electronics',
    
    // Logo image - place file in src/assets/ folder
    // Then specify just the filename here
    logoPath: 'logo.png',
    
    // Logo dimensions in pixels or 'auto'
    logoWidth: 120,
    logoHeight: 'auto',
    
    // Favicon - place file in public/ folder
    // Shown in browser tab next to page title
    faviconPath: 'favicon.ico'
  },

  // Color Palette
  // Note: Variable names represent their UI role, not the actual color
  // Example: 'text' could be white in dark mode, black in light mode
  colors: {
    // Text colors
    text: 'rgba(0, 0, 0, 0.65)',              // Primary text color
    textBold: 'rgba(0, 0, 0, 1)',             // Emphasized text
    shadow: 'rgba(0, 0, 0, 0.1)',             // Shadow/border effects
    background: 'rgba(255, 255, 255, 1)',     // Primary background color
    
    // Primary brand color (used for active states, highlights)
    primary: 'rgba(0, 187, 49, 1)',           // Green
    primaryHover: 'rgba(0, 187, 49, 0.65)',
    primaryShadow: 'rgba(0, 187, 49, 0.1)',
    
    // Secondary accent colors
    secondary: 'rgba(52, 152, 219, 1)',       // Blue
    secondaryHover: 'rgba(52, 152, 219, 0.8)',
    
    // Status colors
    success: 'rgba(0, 187, 49, 1)',           // Green
    warning: 'rgba(255, 140, 0, 1)',          // Orange
    error: 'rgba(244, 67, 54, 1)',            // Red
    errorHover: 'rgba(244, 67, 54, 0.65)',
    
    // Neutral colors
    lightGrey: 'rgba(248, 249, 250, 1)',
    grey: 'rgba(102, 102, 102, 1)'
  },

  // Typography
  typography: {
    fontFamily: "'Roboto', sans-serif",
    
    // Import custom fonts (Google Fonts or local)
    fontImports: [
      '@import url("https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap");'
    ]
  },

  // Layout - All parameters are now fully functional
  layout: {
    // Minimum sidebar width in pixels (grows if content needs more space)
    sidebarInitialWidth: 152,
    
    // Sidebar internal padding (CSS format: 'top right bottom left' or 'vertical horizontal')
    sidebarPadding: '0px 20px',
    
    // Main content area horizontal padding (supports px, vh, em, etc.)
    contentPaddingHorizontal: '4vh',
    
    // Sidebar link button styling
    linkPadding: '10px 15px',          // Internal padding of each link
    linkMargin: '8px 0',                // Spacing between links
    linkBorderRadius: '5px',            // Corner rounding
    
    // Animation settings
    transitionSpeed: '0.1s',            // Duration of hover animations
    hoverTranslateX: '5px'              // Distance links slide on hover
  },

  // External Links - Show custom links at bottom of sidebar
  externalLinks: {
    // Show/hide Flight Review link (boolean)
    showFlightReview: true,
    
    // Add custom external links (array of link objects)
    // Each link can have:
    //   - name: Display text (required)
    //   - url: Link URL (required)
    //   - icon: Font Awesome icon class (optional, defaults to 'fas fa-external-link-alt')
    // All links open in a new tab
    customLinks: [
      // Examples:
      // { 
      //   name: 'Documentation', 
      //   url: 'https://docs.arkelectron.com',
      //   icon: 'fas fa-book'
      // },
      // { 
      //   name: 'GitHub', 
      //   url: 'https://github.com/ARK-Electronics',
      //   icon: 'fab fa-github'
      // },
      // {
      //   name: 'Support',
      //   url: 'https://support.arkelectron.com'
      //   // No icon specified - will use default external link icon
      // }
    ]
  },

  // Advanced: Custom CSS overrides
  // These will be injected as additional CSS rules
  customCSS: `
    /* Add any custom CSS here */
    /* Example:
    .button {
      border-radius: 8px;
    }
    */
  `
};
