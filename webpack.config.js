const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = {
  entry: {
    background: './src/background.js',
    ui: './src/ui.js'
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
        { from: 'manifest.json', to: '.' },
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
  }
};