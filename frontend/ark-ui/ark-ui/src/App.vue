<template>
  <div id="app">
    <div class="sidebar" ref="sidebar">
      <img src="@/assets/logo.png" alt="Logo" class="logo">
      <router-link class="link" :class="{ active: isActive('/') }" to="/">System</router-link>
      <router-link class="link" :class="{ active: isActive('/autopilot-page') }" to="/autopilot-page">Autopilot</router-link>
      <router-link class="link" :class="{ active: isActive('/connections-page') }" to="/connections-page">Connections</router-link>
      <router-link class="link" :class="{ active: isActive('/services-page') }" to="/services-page">Services</router-link>
      <a
        class="link external-link"
        :href="`http://${hostname}.local/flight-review`"
        target="_blank"
        rel="noopener noreferrer"
      >
        <i class="fas fa-external-link-alt"></i> Flight Review
      </a>
    </div>
    <div class="content" :style="{ marginLeft: sidebarWidth + 'px' }">
      <router-view/>
    </div>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  name: 'App',
  data() {
    return {
      sidebarWidth: 152,  // Initial width; will be updated
      hostname: ''
    };
  },
  mounted() {
    this.adjustSidebarWidth();
    this.fetchHostname();
  },
  methods: {
    adjustSidebarWidth() {
      const links = this.$refs.sidebar.querySelectorAll('.link');
      let maxWidth = 0;
      links.forEach(link => {
        maxWidth = Math.max(maxWidth, link.offsetWidth);
      });
      // Adjust for padding and any extra space you might want
      this.sidebarWidth = maxWidth + 40; // Extra 40px for padding
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
:root {
  --ark-color-black: rgba(0, 0, 0, 0.65);
  --ark-color-black-bold: rgba(0, 0, 0, 1);
  --ark-color-black-shadow: rgba(0, 0, 0, 0.1);
  --ark-color-white: rgba(255, 255, 255, 1);
  --ark-color-green: rgba(0, 187, 49, 1);
  --ark-color-green-hover: rgba(0, 187, 49, 0.65);
  --ark-color-green-shadow: rgba(0, 187, 49, 0.1);
  --ark-color-blue: rgba(52, 152, 219, 1);
  --ark-color-red: rgba(244, 67, 54, 1);
  --ark-color-red-hover: rgba(244, 67, 54, 0.65);
  --ark-color-orange: rgba(255, 140, 0, 1);
  --ark-color-light-grey: rgba(248, 249, 250, 1)
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
  padding: 0px 20px;
  display: flex;
  flex-direction: column;
  align-items: start;
  color: var(--ark-color-black); /* Text color black */
  background-color: var(--ark-color-white); /* White background */
  box-shadow: 2px 0 10px var(--ark-color-black-shadow);
}

.link {
  padding: 10px 15px;
  margin: 8px 0;
  border-radius: 5px;
  text-decoration: none; /* No underline */
  transition: all 0.1s ease-in-out;
  white-space: nowrap; /* Prevents text wrapping */
  color: var(--ark-color-black-bold); /* Text color black */
}

.link:hover {
  transform: translateX(5px);
  color: var(--ark-color-white); /* White text on hover */
  background-color: var(--ark-color-green); /* Your green accent color */
}

.link.active {
  color: var(--ark-color-white); /* White text for active link */
  background-color: var(--ark-color-green); /* Green background for active link */
  transform: translateX(5px); /* Same transform as hover for consistency */
  font-weight: bold; /* Make the text bold to stand out more */
}

/* Disable hover effect on active link to avoid visual confusion */
.link.active:hover {
  transform: translateX(5px); /* Keep the same transform to avoid jumps */
}

/* Style for the external link */
.external-link {
  margin-top: auto; /* Push it to the bottom of the sidebar */
  margin-bottom: 20px; /* Add some space at the bottom */
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
  padding-left: 4vh;
  overflow-y: auto; /* Enable scrolling */
  color: var(--ark-color-black-bold); /* Text color black */
  background-color: var(--ark-color-white); /* Light gray background for the content area, change to white if necessary */
}

.logo {
  width: 120px;
  height: auto;
}

</style>
