import { createRouter, createWebHistory } from 'vue-router';
import ServicesPage from '../pages/ServicesPage.vue';
import ConnectionsPage from '../pages/ConnectionsPage.vue';
import AutopilotPage from '../pages/AutopilotPage.vue';
import SystemPage from '../pages/SystemPage.vue';

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
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes
});

export default router;
