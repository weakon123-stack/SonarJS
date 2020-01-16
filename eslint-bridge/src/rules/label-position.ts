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
// https://jira.sonarsource.com/browse/RSPEC-1439

import { Rule } from "eslint";
import * as estree from "estree";

export const rule: Rule.RuleModule = {
  create(context: Rule.RuleContext) {
    return {
      LabeledStatement: (node: estree.Node) =>
        checkLabeledStatement(node as estree.LabeledStatement, context),
    };
  },
};

function checkLabeledStatement(node: estree.LabeledStatement, context: Rule.RuleContext) {
  if (!isLoopStatement(node.body) && !isSwitchStatement(node.body)) {
    context.report({
      message: `Remove this "${node.label.name}" label.`,
      node: node.label,
    });
  }
}

function isLoopStatement(node: estree.Node) {
  return (
    node.type === "WhileStatement" ||
    node.type === "DoWhileStatement" ||
    node.type === "ForStatement" ||
    node.type === "ForOfStatement" ||
    node.type === "ForInStatement"
  );
}

function isSwitchStatement(node: estree.Node) {
  return node.type === "SwitchStatement";
}
