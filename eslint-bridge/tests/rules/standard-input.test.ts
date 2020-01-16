/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2020 SonarSource SA
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

const ruleTester = new RuleTester({ parserOptions: { ecmaVersion: 2018 } });
import { rule } from "../../src/rules/standard-input";

ruleTester.run("Reading the Standard Input is security-sensitive", rule, {
  valid: [
    {
      code: `foo.bar`,
    },
    {
      code: `process.stdout`,
    },
    {
      code: `processFoo.stdin`,
    },
    {
      code: `'process.stdin'`,
    },
  ],
  invalid: [
    {
      code: `let x = process.stdin;`,
      errors: [
        {
          message: "Make sure that reading the standard input is safe here.",
          line: 1,
          endLine: 1,
          column: 9,
          endColumn: 22,
        },
      ],
    },
    {
      code: `process.stdin.on('readable', () => {});`,
      errors: 1,
    },
  ],
});
