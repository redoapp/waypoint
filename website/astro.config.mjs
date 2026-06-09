// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://redoapp.github.io',
  base: '/waypoint',
  integrations: [
    starlight({
      title: 'Waypoint',
      description:
        'Tailscale-aware database proxy: identity-based auth, per-user provisioning, connection limits.',
      customCss: ['./src/styles/verified.css'],
      components: {
        SocialIcons: './src/components/SocialIcons.astro',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/redoapp/waypoint',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/redoapp/waypoint/edit/main/website/',
      },
      sidebar: [
        {
          label: 'Getting Started',
          autogenerate: { directory: 'getting-started' },
        },
        {
          label: 'Configuration',
          autogenerate: { directory: 'configuration' },
        },
        {
          label: 'Listener Modes',
          autogenerate: { directory: 'listeners' },
        },
        {
          label: 'ACL Capability Grants',
          autogenerate: { directory: 'acl' },
        },
        {
          label: 'Tailscale Services',
          link: '/tailscale-services/',
        },
        {
          label: 'Observability',
          autogenerate: { directory: 'observability' },
        },
        {
          label: 'Operations',
          autogenerate: { directory: 'operations' },
        },
      ],
    }),
  ],
});
