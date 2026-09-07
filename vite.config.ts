import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig, Plugin} from 'vite';

// Plugin to prevent Vite dev client from failing on WebSocket connections in sandboxed preview
function disableHmrWebSocketPlugin(): Plugin {
  return {
    name: 'disable-hmr-websocket',
    enforce: 'pre',
    transform(code, id) {
      if (id.includes('client.mjs') || id.includes('@vite/client')) {
        return code
          .replace(
            'const socket = options.createConnection();',
            'return; const socket = options.createConnection();'
          )
          .replace(
            'transport.connect(createHMRHandler(handleMessage));',
            'transport.connect(createHMRHandler(handleMessage)).catch(() => {});'
          );
      }
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [disableHmrWebSocketPlugin(), react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modifyâfile watching is disabled to prevent flickering during agent edits.
      hmr: false,
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
