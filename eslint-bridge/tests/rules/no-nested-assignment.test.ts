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
import { rule } from "../../src/rules/no-nested-assignment";

ruleTester.run("Assignments should not be made from within sub-expressions", rule, {
  valid: [
    {
      code: `let a = 0;`,
    },
    {
      code: `let a = 0, b = 1, c = 2;`,
    },
    {
      code: `let [a, b] = arr;`,
    },
    {
      code: `let {a, b} = obj;`,
    },
    {
      code: `a = 0;`,
    },
    {
      code: `function fun() { a = 0; }`,
    },
    {
      code: `a[i] = 0;`,
    },
    {
      code: `a.prop = 0;`,
    },
    {
      code: `(fun())[i] = 0;`,
    },
    {
      code: `a = b = c = 0;`,
    },
    {
      code: `a = 0, b = 0, c = 0;`,
    },
    {
      code: `({a, b} = obj);`,
    },
    {
      code: `([a, b] = arr);`,
    },
    {
      code: `for (var i = 0;;) {}`,
    },
    {
      code: `for (i = 0;;) {}`,
    },
    {
      code: `for (i = j = 0;;) {}`,
    },
    {
      code: `for (i, j = 0;;) {}`,
    },
    {
      code: `for (;; i = 0) {}`,
    },
    {
      code: `let f = a => b = a;`,
    },
    {
      code: `let f = a => (b = a);`,
    },
  ],
  invalid: [
    {
      code: `if (a = 0) {}`,
      errors: [
        {
          message: `Extract the assignment of "a" from this expression.`,
          line: 1,
          endLine: 1,
          column: 7,
          endColumn: 8,
        },
      ],
    },
    {
      code: `if (a, b = 0) {}`,
      errors: 1,
    },
    {
      code: `if (a = b = 0) {}`,
      errors: 2,
    },
    {
      code: `if ((a = 0) && b) {}`,
      errors: 1,
    },
    {
      code: `if ((fun())[i] = 0) {}`,
      errors: 1,
    },
    {
      code: `(a = 0) ? b : c;`,
      errors: 1,
    },
    {
      code: `a ? b = 0 : c;`,
      errors: 1,
    },
    {
      code: `while (a = 0) {}`,
      errors: 1,
    },
    {
      code: `do {} while (a = 0);`,
      errors: 1,
    },
    {
      code: `fun(a = 0);`,
      errors: 1,
    },
    {
      code: `fun(a = b = c = 0);`,
      errors: 3,
    },
    {
      code: `fun(a, b = 0);`,
      errors: 1,
    },
    {
      code: `for (; i = 0;);`,
      errors: 1,
    },
    {
      code: `for (; i = j = 0;);`,
      errors: 2,
    },
    {
      code: `for (; i, j = 0;);`,
      errors: 1,
    },
    {
      code: `for (; (j = i) === 0;);`,
      errors: 1,
    },
    {
      code: `let a = b = c = 0;`,
      errors: 2,
    },
    {
      code: `let a = (b = (c = 0));`,
      errors: 2,
    },
    {
      code: `let f = a => (a = (b = 0));`,
      errors: 1,
    },
  ],
});
