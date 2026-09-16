const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

// Origin-trial tokens (e.g. Chrome's WebMCP trial) are bound to one extension id and
// expire, so they are never committed. Inject them at build time when needed:
//   EXTENSION_TRIAL_TOKENS=<token>[,<token>] npm run build
// Note: Chrome applies manifest trial tokens to the extension's own pages and service
// worker only, not to scripts injected into web pages.
const trialTokens = (process.env.EXTENSION_TRIAL_TOKENS || '')
  .split(',')
  .map(t => t.trim())
  .filter(Boolean);

function withTrialTokens(content) {
  if (trialTokens.length === 0) return content;
  const manifest = JSON.parse(content.toString());
  manifest.trial_tokens = trialTokens;
  return JSON.stringify(manifest, null, 2);
}

module.exports = {
  entry: {
    background: './src/background.js',
    ui: './src/ui.main.js', // emitted as dist/src/ui.js (referenced by ui.html)
    // WebMCP mode: injected with chrome.scripting.executeScript, so each must be a
    // self-contained classic script (no shared chunks)
    'webmcp-bridge': './src/webmcp-bridge.js', // ISOLATED world
    'webmcp-page': './src/webmcp-page.js'      // MAIN world
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'src/[name].js',
    globalObject: 'self', // Required for MV3 service worker compatibility
    clean: true
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']
          }
        }
      },
      {
        test: /\.css$/i,
        use: ['style-loader', 'css-loader']
      }
    ]
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: 'manifest.json', to: '.', transform: withTrialTokens },
        { from: 'src/*.html', to: '.' },
        { from: 'src/*.css', to: '.' },
        // Ship only the production icon sizes — source artwork lives in assets/
        { from: 'icons/icon*.png', to: 'icons/[name][ext]' }
      ]
    })
  ],
  resolve: {
    fallback: {
      "buffer": false,
      "crypto": false,
      "stream": false
    }
  },
  optimization: {
    minimize: false // Keep readable for debugging
  },
  performance: {
    hints: false // Extension bundles are loaded locally; web asset-size budgets do not apply
  }
};