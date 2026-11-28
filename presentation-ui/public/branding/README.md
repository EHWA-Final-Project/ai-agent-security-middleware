# Branding assets

- `guardon-mark.svg`: original flat shield/G monogram, shared by React BrandMark and the favicon. No external fonts or SVG scripts.
- `ewha-symbol.png`: user-supplied `symbol-mark.png`, copied byte-for-byte without tracing, recoloring or cropping. University text remains visible if loading fails.

To replace the university asset, update the filename in `src/Branding.tsx`; an official SVG can be placed here as `ewha-logo.svg`. Always preserve its original proportions (`object-fit: contain`). All React paths use `import.meta.env.BASE_URL`, and the favicon uses Vite's `%BASE_URL%` so GitHub Pages subpaths work.
