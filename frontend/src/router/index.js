import { createRouter, createWebHistory } from 'vue-router';
import ServicesPage from '../pages/ServicesPage.vue';
import ConnectionsPage from '../pages/ConnectionsPage.vue';
import AutopilotPage from '../pages/AutopilotPage.vue';
import SystemPage from '../pages/SystemPage.vue';
import VideoPage from '../pages/VideoPage.vue';
import LogsPage from '../pages/LogsPage.vue';

const routes = [
  {
    path: '/',
    name: 'SystemPage',
    component: SystemPage
  },
  {
    path: '/autopilot-page',
    name: 'AutopilotPage',
    component: AutopilotPage
  },
  {
    path: '/connections-page',
    name: 'ConnectionsPage',
    component: ConnectionsPage
  },
  {
    path: '/services-page',
    name: 'ServicesPage',
    component: ServicesPage
  },
  {
    path: '/video-page',
    name: 'VideoPage',
    component: VideoPage
  },
  {
    path: '/logs-page',
    name: 'LogsPage',
    component: LogsPage
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes
});

export default router;
