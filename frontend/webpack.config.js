const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const webpack = require("webpack");


module.exports = (env, arg) => {
    const mode = arg.mode;
    const isProduction = mode === 'production';

    return {
        mode: mode ?? 'development',
        entry: './src/index.ts',
        output: {
            filename: 'bundle.js',
            path: path.resolve(__dirname, 'dist'),
            clean: true
        },
        resolve: {
            extensions: ['.ts', '.js', '.svg']
        },
        stats: {
            loggingDebug: ['sass-loader']  // enable @debug statement in scss files.
        },
        devtool: !isProduction && 'source-map',
        module: {
            rules: [
                {
                    test: /\.s[ac]ss$/,
                    use: ['style-loader', 'css-loader', 'sass-loader']
                },
                {
                    test: /\.ts$/,
                    use: 'ts-loader',
                    exclude: /node_modules/
                },
                {
                    test: /\.svg$/,
                    use: {
                        loader: 'file-loader',
                        options: {
                            name: '[path][name].[contenthash].[ext]'
                        }
                    }
                }
            ]
        },
        plugins: [
            new HtmlWebpackPlugin({
                template: './src/index.html',
                filename: 'index.html'
            }),
            new webpack.DefinePlugin({
               SERVER_URL: "\"http://127.0.0.1:4981\""
            })
        ]
    };
}
