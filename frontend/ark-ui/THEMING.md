# ARK-UI Theming Guide

This guide explains how to customize the ARK-UI appearance using the theme configuration system.

## Quick Start

1. **Navigate to ARK-UI directory**: `cd frontend/ark-ui/ark-ui`
2. **Modify Colors**: Edit `src/theme.config.js` and change the color values
3. **Replace Logo**: Place your logo in `src/assets/` and update `logoPath` in theme.config.js
4. **Rebuild**: Run `npm run build` to apply changes

## Theme Files

- **`theme.template.js`** - Documented template with all available options
- **`theme.config.js`** - Active theme configuration (modify this file)
- **`themes/`** - Pre-built theme presets you can copy from

## Customization Guide

### 1. Changing Colors

Edit `src/theme.config.js`:

```javascript
colors: {
  primary: 'rgba(255, 0, 0, 1)',      // Change to red
  primaryHover: 'rgba(255, 0, 0, 0.8)',
  // ... other colors
}
```

**Available color variables:**
- `primary` - Main brand color (sidebar active states, buttons)
- `secondary` - Accent color (links, info elements)
- `success` - Success states (green by default)
- `warning` - Warning states (orange by default)  
- `error` - Error states (red by default)
- `black/white` - Text and backgrounds
- `grey/lightGrey` - Borders, disabled states

### 2. Changing Logo

**Step 1:** Place your logo image in `src/assets/`
```bash
cp /path/to/your/logo.png src/assets/custom-logo.png
```

**Step 2:** Update `theme.config.js`:
```javascript
branding: {
  logoPath: 'custom-logo.png',
  logoWidth: 150,              // Adjust size
  logoHeight: 'auto'
}
```

### 3. Changing Fonts

**Using Google Fonts:**
```javascript
typography: {
  fontFamily: "'Open Sans', sans-serif",
  fontImports: [
    '@import url("https://fonts.googleapis.com/css2?family=Open+Sans:wght@300;400;700&display=swap");'
  ]
}
```

**Using Local Fonts:**
1. Place font files in `src/assets/fonts/`
2. Update theme.config.js:
```javascript
typography: {
  fontFamily: "'MyCustomFont', sans-serif",
  fontImports: [
    `@font-face {
      font-family: 'MyCustomFont';
      src: url('./assets/fonts/MyFont.woff2') format('woff2');
    }`
  ]
}
```

### 4. Adding Custom Links

Add external links to the sidebar (displayed at the bottom):

**Step 1:** Edit `externalLinks` in `theme.config.js`:
```javascript
externalLinks: {
  showFlightReview: true,  // Show/hide built-in Flight Review link
  
  customLinks: [
    {
      name: 'Documentation',                    // Display text (required)
      url: 'https://docs.arkelectron.com',     // Link URL (required)
      icon: 'fas fa-book'                       // Font Awesome icon (optional)
    },
    {
      name: 'GitHub',
      url: 'https://github.com/ARK-Electronics',
      icon: 'fab fa-github'
    },
    {
      name: 'Support',
      url: 'https://support.arkelectron.com'
      // No icon specified - uses default external link icon
    }
  ]
}
```

**Available Icons:**
Custom links support Font Awesome icons. See [fontawesome.com/icons](https://fontawesome.com/icons) for the full list.

**Common icons:**
- `fas fa-book` - Documentation
- `fab fa-github` - GitHub
- `fas fa-question-circle` - Support/Help
- `fas fa-envelope` - Contact
- `fas fa-globe` - Website
- `fab fa-slack` - Slack
- `fab fa-discord` - Discord

**Link behavior:**
- All custom links open in a new tab
- Links are displayed at the bottom of the sidebar
- Order matches array order in config

**Hide Flight Review:**
```javascript
externalLinks: {
  showFlightReview: false,  // Hide built-in link
  customLinks: []
}
```

### 5. Using Theme Presets

Copy from pre-built themes:

**Dark Mode:**
```bash
cp src/themes/dark.theme.js src/theme.config.js
```

**Blue Theme:**
```bash
cp src/themes/blue.theme.js src/theme.config.js
```

### 6. Advanced Customization

Add custom CSS rules:

```javascript
customCSS: `
  /* Round all buttons */
  .button {
    border-radius: 20px !important;
  }
  
  /* Change sidebar width */
  .sidebar {
    width: 200px !important;
  }
  
  /* Add gradient background */
  .content {
    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%) !important;
  }
`
```

## Color Format

Use RGBA format for all colors:
```javascript
'rgba(red, green, blue, alpha)'
```

Where:
- `red`, `green`, `blue`: 0-255
- `alpha`: 0-1 (0 = transparent, 1 = opaque)

**Examples:**
- Solid red: `rgba(255, 0, 0, 1)`
- Semi-transparent blue: `rgba(0, 0, 255, 0.5)`
- Black with 65% opacity: `rgba(0, 0, 0, 0.65)`

## Favicon

Replace `public/favicon.ico` with your custom favicon, or:

1. Place favicon in `public/`
2. Update theme.config.js:
```javascript
branding: {
  faviconPath: 'my-favicon.ico'
}
```

## Testing Changes

**Important:** All commands must be run from the `frontend/ark-ui/ark-ui` directory:

```bash
cd frontend/ark-ui/ark-ui
```

**Development mode:**
```bash
npm run serve
```
Changes to theme.config.js require a page refresh (Ctrl+Shift+R for hard refresh).
Server runs at http://localhost:8080/

**Production build:**
```bash
npm run build
```
Creates optimized files in the `dist/` folder.

**Viewing the production build:**
After building, you need to serve the dist folder with a web server:
```bash
# Install serve globally (one-time setup)
npm install -g serve

# Serve the production build
serve -s dist
```
Then open the URL shown in terminal (usually http://localhost:3000/)

## Tips

- Use online color pickers to get RGBA values
- Maintain sufficient contrast for accessibility (dark text on light backgrounds)
- Test your theme on different screen sizes
- Keep a backup of your theme.config.js before major changes
- Use the same alpha values for hover states (0.65-0.8 works well)

## Example: Complete Custom Brand

```javascript
export default {
  branding: {
    name: 'Acme Drones',
    logoPath: 'acme-logo.svg',
    logoWidth: 140,
    logoHeight: 'auto',
    faviconPath: 'acme-favicon.ico'
  },
  
  colors: {
    black: 'rgba(33, 33, 33, 1)',
    blackBold: 'rgba(0, 0, 0, 1)',
    blackShadow: 'rgba(0, 0, 0, 0.15)',
    white: 'rgba(255, 255, 255, 1)',
    
    primary: 'rgba(106, 27, 154, 1)',        // Purple
    primaryHover: 'rgba(106, 27, 154, 0.85)',
    primaryShadow: 'rgba(106, 27, 154, 0.1)',
    
    secondary: 'rgba(255, 193, 7, 1)',       // Amber
    secondaryHover: 'rgba(255, 193, 7, 0.8)',
    
    success: 'rgba(76, 175, 80, 1)',
    warning: 'rgba(255, 152, 0, 1)',
    error: 'rgba(244, 67, 54, 1)',
    errorHover: 'rgba(244, 67, 54, 0.8)',
    
    lightGrey: 'rgba(250, 250, 250, 1)',
    grey: 'rgba(117, 117, 117, 1)'
  },
  
  typography: {
    fontFamily: "'Montserrat', sans-serif",
    fontImports: [
      '@import url("https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&display=swap");'
    ]
  },
  
  layout: {
    sidebarInitialWidth: 180,
    sidebarPadding: '0px 25px',
    contentPaddingHorizontal: '5vh',
    linkPadding: '12px 18px',
    linkMargin: '10px 0',
    linkBorderRadius: '8px',
    transitionSpeed: '0.15s',
    hoverTranslateX: '8px'
  },
  
  externalLinks: {
    showFlightReview: true,
    customLinks: [
      {
        name: 'Acme Docs',
        url: 'https://docs.acmedrones.com',
        icon: 'fas fa-book'
      },
      {
        name: 'Support Portal',
        url: 'https://support.acmedrones.com',
        icon: 'fas fa-headset'
      }
    ]
  },
  
  // ... rest of config
};
```

## Troubleshooting

**Colors not changing:**
- Clear browser cache and hard refresh (Ctrl+Shift+R)
- Check browser console for errors
- Verify RGBA format is correct

**Logo not showing:**
- Verify file path is correct relative to `src/assets/`
- Check file exists and has correct permissions
- Try absolute URL for testing

**Build errors:**
- Validate JavaScript syntax in theme.config.js
- Ensure all quotes are properly closed
- Check for trailing commas in objects
