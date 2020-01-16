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

const parser = path.resolve(`${__dirname}/../node_modules/@typescript-eslint/parser`);

const parserOptions = {
  ecmaVersion: 2018,
  sourceType: "module",
  project: path.resolve(`${__dirname}/fixtures/rule-tester-project/tsconfig.json`),
};

const placeHolderFilePath = path.resolve(`${__dirname}/fixtures/rule-tester-project/file.tsx`);

/**
 * Rule tester for Typescript, using @typescript-eslint parser, making sure that type information is present.
 * It will also assert that no issues is raised when there are no type information.
 */
class RuleTesterTs extends RuleTester {
  ruleTesterNoTsConfig = new RuleTester({
    parser,
    parserOptions: {
      ecmaVersion: 2018,
      sourceType: "module",
      ecmaFeatures: {
        jsx: true,
        globalReturn: true,
      },
    },
  });

  constructor() {
    super({
      parser,
      parserOptions,
    });
  }

  run(
    name: string,
    rule: Rule.RuleModule,
    tests: {
      valid?: RuleTester.ValidTestCase[];
      invalid?: RuleTester.InvalidTestCase[];
    },
  ): void {
    this.ruleTesterNoTsConfig.run(`${name}[noTsConfig]`, rule, {
      valid: tests.invalid,
      invalid: [],
    });

    tests.valid.forEach(test => {
      if (!test.filename) {
        test.filename = placeHolderFilePath;
      }
    });
    tests.invalid.forEach(test => {
      if (!test.filename) {
        test.filename = placeHolderFilePath;
      }
    });

    super.run(name, rule, tests);
  }
}

export { RuleTesterTs };
