const CopyPlugin = require('copy-webpack-plugin');
const { join } = require('path');

module.exports = (config, options) => {
  config.plugins.push(
    new CopyPlugin({
      patterns: [
        {
          from: join(__dirname, 'src', 'templates'),
          to:   join(__dirname, 'dist', 'templates'),
          globOptions: {
            ignore: ['**/*.ts'],
          },
        },
      ],
    })
  );
  return config;
};