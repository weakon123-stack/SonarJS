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
import { RuleTesterTs } from "../RuleTesterTs";
import { rule } from "../../src/rules/no-invalid-await";

const ruleTester = new RuleTesterTs();
ruleTester.run("await should only be used with promises.", rule, {
  valid: [
    {
      code: `
      async function foo() {
        await ({then() { }});
      }
      `,
    },
    {
      code: `
      async function foo() {
        await Promise.resolve(42);
      }
      `,
    },
    {
      code: `
      async function foo(p: PromiseLike<any>) {
        await p;
      }
      `,
    },
    {
      code: `
      class MyPromiseLike implements PromiseLike<any> {
        then(){}
      }
      async function foo() {
        await new MyPromiseLike();
      }
      `,
    },
    {
      code: `
      class MyPromiseLike implements PromiseLike<any> {
        then(){}
      }
      class MyPromiseLike2 extends MyPromiseLike {
        then(){}
      }
      async function foo() {
        await new MyPromiseLike2();
      }
      `,
    },
    {
      code: `
      class MyPromise implements Promise<any> {
        then(){}
      }
      async function foo() {
        await new MyPromise();
      }
      `,
    },
    {
      code: `
      interface Thenable<T> {
        then: () => T
      }
      class MyThenable implements Thenable<number> {
        then() {
          return 1;
        }
      }
      async function foo() {
        await new MyThenable();
      }
      `,
    },
    {
      code: `
      import { NotExisting } from "invalid";
      async function foo() {
        await new NotExisting();
      }
      `,
    },
    {
      code: `
      function returnNumber(): number | Promise<number> {
        return 1
      }
      async function foo() {
        await returnNumber();
      }
      `,
    },
  ],
  invalid: [
    {
      code: `
      async function foo() {
        let arr = [1, 2, 3];
        await arr;
      }
      `,
      errors: [
        {
          message: "Refactor this redundant 'await' on a non-promise.",
          line: 4,
          endLine: 4,
          column: 9,
          endColumn: 18,
        },
      ],
    },
    {
      code: `
      async function foo() {
        let x: number = 1;
        await x;
      }
      `,
      errors: 1,
    },
    {
      code: `
      async function foo() {
        await 1;
      }
      `,
      errors: 1,
    },
    {
      code: `
      async function foo() {
        await {else: 42};
      }
      `,
      errors: 1,
    },
    {
      code: `
      async function foo() {
        await {then: 42};
      }
      `,
      errors: 1,
    },
  ],
});
