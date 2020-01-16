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
// https://jira.sonarsource.com/browse/RSPEC-1523
// SQ key 'eval'

import { Rule } from "eslint";
import * as estree from "estree";

export const rule: Rule.RuleModule = {
  create(context: Rule.RuleContext) {
    return {
      CallExpression: (node: estree.Node) =>
        checkCallExpression(node as estree.CallExpression, context),
      NewExpression: (node: estree.Node) =>
        checkCallExpression(node as estree.CallExpression, context),
    };
  },
};

function checkCallExpression(node: estree.CallExpression, context: Rule.RuleContext) {
  if (node.callee.type === "Identifier") {
    const { name } = node.callee;
    if ((name === "eval" || name === "Function") && hasAtLeastOneVariableArgument(node.arguments)) {
      context.report({
        message: `Make sure that this dynamic injection or execution of code is safe.`,
        node: node.callee,
      });
    }
  }
}

function hasAtLeastOneVariableArgument(args: Array<estree.Node>) {
  return !!args.find(arg => !isLiteral(arg));
}

function isLiteral(node: estree.Node) {
  if (node.type === "Literal") {
    return true;
  }

  if (node.type === "TemplateLiteral") {
    return node.expressions.length === 0;
  }

  return false;
}
