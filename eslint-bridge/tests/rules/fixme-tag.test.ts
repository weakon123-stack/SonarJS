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
import { rule } from "../../src/rules/fixme-tag";

ruleTester.run("Track uses of FIXME tags", rule, {
  valid: [
    {
      code: `// Just a regular comment`,
    },
    {
      code: `
        // This is not aFIXME comment

        // notafixme comment

        // a fixmeal
        `,
    },
  ],
  invalid: [
    {
      code: `// FIXME`,
      errors: [
        {
          message: "Take the required action to fix the issue indicated by this comment.",
          line: 1,
          endLine: 1,
          column: 4,
          endColumn: 9,
        },
      ],
    },

    {
      code: `/*FIXME Multiline comment 
      FIXME: another fixme
      (this line is not highlighted)
      with three fixme
      */`,
      errors: [
        {
          message: "Take the required action to fix the issue indicated by this comment.",
          line: 1,
          endLine: 1,
          column: 3,
          endColumn: 8,
        },
        {
          message: "Take the required action to fix the issue indicated by this comment.",
          line: 2,
          endLine: 2,
          column: 7,
          endColumn: 12,
        },
        {
          message: "Take the required action to fix the issue indicated by this comment.",
          line: 4,
          endLine: 4,
          column: 18,
          endColumn: 23,
        },
      ],
    },
    {
      code: `// FIXME  FIXME`,
      errors: 1,
    },
    {
      code: `
      // FIXME just fix me 

      // FixMe just fix me 

      //fixme comment

      // This is a FIXME just fix me 

      // fixme: things to do

      // :FIXME: things to do

      // valid end of line fixme

      /*
      FIXME Multiline comment 
      */

      /*
      FIXME Multiline comment 

        with two fixme
      */

      // valid end of file FIXME
        `,
      errors: 11,
    },
  ],
});
