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

const ruleTester = new RuleTesterTs();

import { rule } from "../../src/rules/no-in-misuse";

ruleTester.run('"in" should not be used on arrays"', rule, {
  valid: [
    {
      code: `const dict = {a: 1, b: 2, c: 3};
            "a" in dict;  // OK on objects`,
    },
    {
      code: `function okOnArrayLikeObjects(a: any, b: any) {
                let key = "1";
                if (key in arguments) {
                return "Something";
                }
                return "Something else";
              }`,
    },
  ],
  invalid: [
    {
      code: `// to check the property of an object do this
                "car" in { "car" : 1};
                // and not this
                "car" in Object.keys({ "car": 1 }); // Noncompliant`,
      errors: [
        {
          message: `Use "indexOf" or "includes" (available from ES2016) instead.`,
          line: 4,
          column: 17,
          endLine: 4,
          endColumn: 51,
        },
      ],
    },
    {
      code: `let arr = ["a", "b", "c"];
            "1" in arr; // Noncompliant
            1 in arr; // Noncompliant
            "b" in arr; // Noncompliant`,
      errors: 3,
    },
    {
      code: `// in different contexts
            let arr = ["a", "b", "c"];
            const result = "car" in arr ? "something" : "something else"; // Noncompliant
            foo("car" in arr); // Noncompliant
            if ("car" in arr) {} // Noncompliant`,
      errors: 3,
    },
    {
      code: `function erroneousIncludesES2016(array: any[], elem: any) {
                    return elem in array; // Noncompliant
                }`,
      errors: 1,
    },
  ],
});
