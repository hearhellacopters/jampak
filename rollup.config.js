import typescript from '@rollup/plugin-typescript';
import dts from 'rollup-plugin-dts';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import jsonRollUp from "@rollup/plugin-json";

export default [
  // ── 1. CommonJS (Node require)
  {
    input: './src/index.ts',
    output: [
      {
        file: './dist/index.cjs.js',
        format: 'cjs',
        exports: 'named',
        sourcemap: true
      }
    ],
    plugins: [
      nodeResolve(),
      commonjs(),
      jsonRollUp(),
      typescript(
        {
          "target": "ES2020",
          "module": "ESNext",
          "declaration": false,
          "outDir": "./dist",
          "rootDir": "./src",
          "moduleResolution": "node",
          "esModuleInterop": true,
          "skipLibCheck": true
        }
      )
    ],
    external: [
      'fs', 
      'buffer', 
      //"bireader"
    ]
  },

  // ── 2. ESM (Node import + modern bundlers)
  {
    input: './src/index.ts',
    output: [
      {
        file: './dist/index.esm.js',
        format: 'es',
        sourcemap: true
      }
    ],
    plugins: [
      nodeResolve({ preferBuiltins: true, browser: false }),
      commonjs(),
      jsonRollUp(),
      typescript({
        tsconfig: './tsconfig.esm.json',
        declaration: false
      })
    ],
    external: [
      'fs', 
      'buffer', 
      //"bireader"
    ]
  },

  // ── 3. Types build
  {
    input: 'src/index.ts',
    output: {
      file: './dist/index.d.ts',
      format: 'es'
    },
    plugins: [
      dts({
        tsconfig: './tsconfig.d.ts.json'
      })
    ],
    external: [
      'fs', 
      'buffer', 
      //"bireader"
    ]
  },

  // Types build
  {
    input: './dist/index.d.ts',
    output: {
      file: './dist/index.esm.d.ts',
      format: 'es'
    },
    plugins: [dts({
      tsconfig: './tsconfig.d.ts.json'
    })]
  },
  {
    input: './dist/index.d.ts',
    output: {
      file: './dist/index.cjs.d.ts',
      format: 'cjs'
    },
    plugins: [dts({
      tsconfig: './tsconfig.d.ts.json'
    })]
  }
];
