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
// https://jira.sonarsource.com/browse/RSPEC-1527

import { Rule, Scope } from "eslint";

const futureReservedWords = [
  "implements",
  "interface",
  "package",
  "private",
  "protected",
  "public",
  "enum",
  "class",
  "const",
  "export",
  "extends",
  "import",
  "super",
  "let",
  "static",
  "yield",
  "await",
];

export const rule: Rule.RuleModule = {
  create(context: Rule.RuleContext) {
    function checkVariable(variable: Scope.Variable) {
      if (variable.defs.length > 0) {
        const def = variable.defs[0].name;
        context.report({
          node: def,
          message: `Rename "${
            variable.name
          }" identifier to prevent potential conflicts with future evolutions of the JavaScript language.`,
        });
      }
    }

    function checkVariablesByScope(scope: Scope.Scope) {
      scope.variables.filter(v => futureReservedWords.includes(v.name)).forEach(checkVariable);

      scope.childScopes.forEach(childScope => {
        checkVariablesByScope(childScope);
      });
    }

    return {
      "Program:exit": () => {
        checkVariablesByScope(context.getScope());
      },
    };
  },
};
