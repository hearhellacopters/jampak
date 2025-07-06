import typescript from '@rollup/plugin-typescript';
import dts from 'rollup-plugin-dts';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import jsonRollUp from "@rollup/plugin-json";

export default [
  // JS build (CJS + ESM)
  {
    input: './src/index.ts',
    output: [
      {
        file: './dist/index.cjs.js',
        format: 'cjs',
        exports: 'named',
        sourcemap: true
      },
      {
        file: './dist/index.esm.js',
        format: 'esm',
        sourcemap: true
      }
    ],
    plugins: [
      nodeResolve(),
      commonjs(),
      jsonRollUp(),
      typescript({ tsconfig: './tsconfig.json' })
    ],
    external: ['fs', 'buffer', "bireader"] // Node built-ins
  },
  // Types build
  {
    input: './dist/index.d.ts',
    output: {
      file: './dist/index.esm.d.ts',
      format: 'es'
    },
    plugins: [dts()]
  },
  {
    input: './dist/index.d.ts',
    output: {
      file: './dist/index.d.ts',
      format: 'es'
    },
    plugins: [dts()]
  },
  {
    input: './dist/index.d.ts',
    output: {
      file: './dist/index.cjs.d.ts',
      format: 'cjs'
    },
    plugins: [dts()]
  }
];
