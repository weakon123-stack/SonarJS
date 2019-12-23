/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2019 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
import { RuleTester } from "eslint";
import * as fs from "fs";

const ruleTester = new RuleTester({
  parserOptions: { ecmaVersion: 2018, sourceType: "module" },
  parser: require.resolve("babel-eslint"),
});
import { rule } from "../../src/rules/unused-import";

ruleTester.run("Unnecessary imports should be removed", rule, {
  valid: [
    // {
    //   code: `
    //   import a from 'b';
    //   console.log(a);
    //   `,
    // },
    // {
    //   code: `
    //   import { a } from 'b';
    //   console.log(a);
    //   `,
    // },
    // {
    //   code: `
    //   import { a, b } from 'c';
    //   console.log(a);
    //   console.log(b);
    //   `,
    // },
    // {
    //   code: `
    //   import { a as b } from 'c';
    //   console.log(b);
    //   `,
    // },
    // {
    //   code: `import React from 'react';`,
    // },
    // {
    //   code: `
    //   import { a } from 'b';
    //   <a />
    //   `,
    // },
    // {
    //   code: `
    //   /* @flow */
    //   import type { a } from 'b';
    //   export const c = (d: a): e => {}
    //   `,
    // },
    {
      code: fs.readFileSync(
        "/Users/yassin/Development/sonar-js/its/sources/src/babylon/src/index.js",
        { encoding: "utf8" },
      ),
    },
  ],
  invalid: [
    // {
    //   code: `import a from 'b';`,
    //   errors: [
    //     {
    //       message: `Remove this unused import of 'a'.`,
    //       line: 1,
    //       endLine: 1,
    //       column: 8,
    //       endColumn: 9,
    //     },
    //   ],
    // },
    // {
    //   code: `import { a } from 'b';`,
    //   errors: 1,
    // },
    // {
    //   code: `import { a, b } from 'c';`,
    //   errors: 2,
    // },
    // {
    //   code: `
    //   import { a, b } from 'c';
    //   console.log(b);
    //   `,
    //   errors: 1,
    // },
    // {
    //   code: `import * as a from 'b';`,
    //   errors: 1,
    // },
    // {
    //   code: `import { a as b } from 'c';`,
    //   errors: 1,
    // },
    // {
    //   code: `import typeof a from 'b';`,
    //   errors: 1,
    // },
    // {
    //   code: `import React, { Component } from 'react';`,
    //   errors: 1,
    // },
  ],
});
