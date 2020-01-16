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
import { rule } from "../../src/rules/comment-regex";

const optionsWithouthMessage = [{ regularExpression: "[a-z]" }];
const optionsWithMessage = [{ regularExpression: "[a-z]", message: "this is a message" }];

ruleTester.run("Track comments matching a regular expression", rule, {
  valid: [
    {
      code: `
        // No options means that no comment are reported.
        `,
    },
    {
      code: `
        // THE COMMENT DO NOT MATCH THE REGEX
        `,
      options: optionsWithMessage,
    },
    {
      code: `
        // THE COMMENT DO NOT MATCH THE REGEX
        `,
      options: optionsWithouthMessage,
    },
  ],
  invalid: [
    {
      code: `// options with a message!`,
      options: optionsWithMessage,
      errors: [
        {
          message: "this is a message",
          line: 1,
          endLine: 1,
          column: 1,
          endColumn: 27,
        },
      ],
    },
    {
      code: `// options without a message!`,
      options: optionsWithouthMessage,
      errors: [
        {
          message: "The regular expression matches this comment.",
          line: 1,
          endLine: 1,
          column: 1,
          endColumn: 30,
        },
      ],
    },
  ],
});
