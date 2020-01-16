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
import { RuleTester, Rule } from "eslint";
import * as path from "path";

interface TestCases {
  valid: RuleTester.ValidTestCase[];
  invalid: RuleTester.InvalidTestCase[];
}

const parserOptions = {
  ecmaVersion: 2018,
  sourceType: "module",
};

export default class Ruler {
  private readonly ruleTesterJs = new RuleTester({
    parserOptions,
  });

  private readonly ruleTesterTs = new RuleTester({
    parser: require.resolve("@typescript-eslint/parser"),
    parserOptions: {
      ...parserOptions,
      project: path.resolve(`${__dirname}/fixtures/rule-tester-project/tsconfig.json`),
    },
  });

  run(name: string, rule: Rule.RuleModule, tests: { js: TestCases; ts: TestCases }) {
    const filename = path.resolve(`${__dirname}/fixtures/rule-tester-project/file.ts`);
    tests.ts.valid.forEach(testCase => (testCase.filename = filename));
    tests.ts.invalid.forEach(testCase => (testCase.filename = filename));
    this.ruleTesterJs.run(`${name}\n   javascript`, rule, tests.js);
    this.ruleTesterTs.run(" typescript", rule, tests.ts);
  }
}
