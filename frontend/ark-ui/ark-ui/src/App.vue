<template>
  <div id="app">
    <div class="sidebar" ref="sidebar" :style="{ width: sidebarWidth + 'px' }">
      <img :src="require(`@/assets/${theme.branding.logoPath}`)" :alt="theme.branding.name" class="logo" :style="{ width: theme.branding.logoWidth + 'px', height: theme.branding.logoHeight }">
      <router-link class="link" :class="{ active: isActive('/') }" to="/">System</router-link>
      <router-link class="link" :class="{ active: isActive('/autopilot-page') }" to="/autopilot-page">Autopilot</router-link>
      <router-link class="link" :class="{ active: isActive('/connections-page') }" to="/connections-page">Connections</router-link>
      <router-link class="link" :class="{ active: isActive('/services-page') }" to="/services-page">Services</router-link>
      <div class="external-links-container">
        <a
          v-if="theme.externalLinks.showFlightReview"
          class="link external-link"
          :href="`http://${hostname}.local/flight-review`"
          target="_blank"
          rel="noopener noreferrer"
        >
          <i class="fas fa-external-link-alt"></i> Flight Review
        </a>
        <a
          v-for="(link, index) in theme.externalLinks.customLinks"
          :key="index"
          class="link external-link"
          :href="link.url"
          target="_blank"
          rel="noopener noreferrer"
        >
          <i :class="link.icon || 'fas fa-external-link-alt'"></i> {{ link.name }}
        </a>
      </div>
    </div>
    <div class="content" :style="{ marginLeft: sidebarWidth + 'px' }">
      <router-view/>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import themeConfig from './theme.config.js';

export default {
  name: 'App',
  data() {
    return {
      sidebarWidth: themeConfig.layout.sidebarInitialWidth,
      hostname: '',
      theme: themeConfig
    };
  },
  mounted() {
    this.applyTheme();
    this.adjustSidebarWidth();
    this.fetchHostname();
  },
  methods: {
    applyTheme() {
      console.log('Applying theme:', this.theme.branding.name);
      console.log('Colors:', this.theme.colors);
      
      // Set browser tab title
      document.title = this.theme.branding.name;
      
      // Set favicon
      const favicon = document.querySelector("link[rel*='icon']") || document.createElement('link');
      favicon.type = 'image/x-icon';
      favicon.rel = 'shortcut icon';
      favicon.href = this.theme.branding.faviconPath;
      document.head.appendChild(favicon);
      
      // Apply CSS variables from theme config
      const root = document.documentElement;
      const colors = this.theme.colors;
      
      root.style.setProperty('--ark-color-black', colors.text);
      root.style.setProperty('--ark-color-black-bold', colors.textBold);
      root.style.setProperty('--ark-color-black-shadow', colors.shadow);
      root.style.setProperty('--ark-color-white', colors.background);
      root.style.setProperty('--ark-color-green', colors.primary);
      root.style.setProperty('--ark-color-green-hover', colors.primaryHover);
      root.style.setProperty('--ark-color-green-shadow', colors.primaryShadow);
      root.style.setProperty('--ark-color-blue', colors.secondary);
      root.style.setProperty('--ark-color-blue-hover', colors.secondaryHover);
      root.style.setProperty('--ark-color-red', colors.error);
      root.style.setProperty('--ark-color-red-hover', colors.errorHover);
      root.style.setProperty('--ark-color-orange', colors.warning);
      root.style.setProperty('--ark-color-light-grey', colors.lightGrey);
      root.style.setProperty('--ark-color-grey', colors.grey);
      
      // Apply layout variables from theme config
      const layout = this.theme.layout;
      root.style.setProperty('--ark-sidebar-padding', layout.sidebarPadding);
      root.style.setProperty('--ark-content-padding-horizontal', layout.contentPaddingHorizontal);
      root.style.setProperty('--ark-link-padding', layout.linkPadding);
      root.style.setProperty('--ark-link-margin', layout.linkMargin);
      root.style.setProperty('--ark-link-border-radius', layout.linkBorderRadius);
      root.style.setProperty('--ark-transition-speed', layout.transitionSpeed);
      root.style.setProperty('--ark-hover-translate-x', layout.hoverTranslateX);
      
      console.log('Theme applied successfully');
      
      // Apply custom CSS if provided
      if (this.theme.customCSS) {
        const styleEl = document.createElement('style');
        styleEl.textContent = this.theme.customCSS;
        document.head.appendChild(styleEl);
      }
    },
    adjustSidebarWidth() {
      const links = this.$refs.sidebar.querySelectorAll('.link');
      let maxWidth = 0;
      links.forEach(link => {
        maxWidth = Math.max(maxWidth, link.offsetWidth);
      });
      // Use the greater of: calculated width or configured initial width
      this.sidebarWidth = Math.max(maxWidth + 10, this.theme.layout.sidebarInitialWidth);
    },
    fetchHostname() {
      axios.get('/api/system/info')
        .then(response => {
          // Extract hostname from the info object
          if (response.data && response.data.interfaces && response.data.interfaces.hostname) {
            this.hostname = response.data.interfaces.hostname;
          } else {
            console.error('Hostname not found in system info response');
          }
        })
        .catch(error => {
          console.error('Error fetching system info:', error);
        });
    },
    isActive(routePath) {
      return this.$route.path === routePath;
    }
  }
};
</script>

<style>
/* CSS variables are set dynamically by applyTheme() method */

body {
  margin: 0;
  padding: 0;
  background-color: var(--ark-color-white);
}

#app {
  display: flex;
  font-family: 'Roboto', sans-serif;
  color: var(--ark-color-black); /* Should be your black color */
  background-color: var(--ark-color-white); /* Your specified white color */
}

.sidebar {
  position: fixed;
  height: 100vh; /* Full height */
  left: 0;
  top: 0;
  padding: var(--ark-sidebar-padding);
  padding-bottom: 20px;
  display: flex;
  flex-direction: column;
  align-items: start;
  color: var(--ark-color-black); /* Text color black */
  background-color: var(--ark-color-white); /* White background */
  box-shadow: 2px 0 10px var(--ark-color-black-shadow);
}

.link {
  padding: var(--ark-link-padding);
  margin: var(--ark-link-margin);
  border-radius: var(--ark-link-border-radius);
  text-decoration: none; /* No underline */
  transition: all var(--ark-transition-speed) ease-in-out;
  white-space: nowrap; /* Prevents text wrapping */
  color: var(--ark-color-black-bold); /* Text color black */
}

.link:hover {
  transform: translateX(var(--ark-hover-translate-x));
  color: var(--ark-color-white); /* White text on hover */
  background-color: var(--ark-color-green); /* Your green accent color */
}

.link.active {
  color: var(--ark-color-white); /* White text for active link */
  background-color: var(--ark-color-green); /* Green background for active link */
  transform: translateX(var(--ark-hover-translate-x)); /* Same transform as hover for consistency */
  font-weight: bold; /* Make the text bold to stand out more */
}

/* Disable hover effect on active link to avoid visual confusion */
.link.active:hover {
  transform: translateX(var(--ark-hover-translate-x)); /* Keep the same transform to avoid jumps */
}

/* External links container */
.external-links-container {
  margin-top: auto;
  padding-top: 20px;
  display: flex;
  flex-direction: column;
}

/* Style for the external link */
.external-link {
  display: flex;
  align-items: center;
  color: var(--ark-color-black-bold); /* Different color for external link */
}

.external-link:hover {
  background-color: var(--ark-color-white-hover); /* Hover effect for the external link */
  color: var(--ark-color-blue); /* White text on hover */
}

.external-link i {
  margin-right: 8px; /* Space between icon and text */
}

.content {
  flex-grow: 1;
  padding-left: var(--ark-content-padding-horizontal);
  padding-right: var(--ark-content-padding-horizontal);
  overflow-y: auto; /* Enable scrolling */
  color: var(--ark-color-black-bold); /* Text color black */
  background-color: var(--ark-color-white); /* Light gray background for the content area, change to white if necessary */
}

.logo {
  width: 120px;
  height: auto;
}

</style>
