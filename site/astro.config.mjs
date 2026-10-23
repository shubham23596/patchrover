import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const site = process.env.SITE_URL || 'https://patchrover.invalid';
const base = process.env.BASE_PATH || '/';

export default defineConfig({
  site,
  base,
  integrations: [
    starlight({
      title: 'PatchRover',
      description: 'Track a critical vulnerability from advisory to the workload actually running.',
      disable404Route: true,
      logo: { src: './src/assets/rover-mark.svg', alt: 'PatchRover' },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/starlight.css'],
      social: process.env.PUBLIC_GITHUB_URL
        ? [{ icon: 'github', label: 'GitHub', href: process.env.PUBLIC_GITHUB_URL }]
        : [],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Getting started', slug: 'getting-started' },
            { label: 'CLI reference', slug: 'cli' },
            { label: 'Autonomous agent', slug: 'autonomous-agent' }
          ]
        },
        {
          label: 'Core concepts',
          items: [
            { label: 'Packs, trails, and receipts', slug: 'concepts' },
            { label: 'Response Pack v1alpha1', slug: 'response-pack' },
            { label: 'Security model', slug: 'security-model' },
            { label: 'Limitations', slug: 'limitations' }
          ]
        },
        {
          label: 'Project',
          items: [
            { label: 'Governance', slug: 'governance' },
            { label: 'Roadmap', slug: 'roadmap' },
            { label: 'Contributing', slug: 'contributing' },
            { label: 'Commercial edition', slug: 'commercial' }
          ]
        }
      ],
      editLink: process.env.PUBLIC_GITHUB_URL
        ? { baseUrl: `${process.env.PUBLIC_GITHUB_URL}/edit/main/site/` }
        : undefined
    })
  ]
});
