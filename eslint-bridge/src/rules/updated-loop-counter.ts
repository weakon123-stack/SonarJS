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
// https://jira.sonarsource.com/browse/RSPEC-2310

import { Rule } from "eslint";
import * as estree from "estree";
import { getVariableFromName, resolveIdentifiers, toEncodedMessage } from "./utils";
import { getParent } from "eslint-plugin-sonarjs/lib/utils/nodes";
import { TSESTree } from "@typescript-eslint/experimental-utils";

export const rule: Rule.RuleModule = {
  meta: {
    schema: [
      {
        // internal parameter for rules having secondary locations
        enum: ["sonar-runtime"],
      },
    ],
  },

  create(context: Rule.RuleContext) {
    function checkLoop<T>(
      updateNode: T,
      extractCounters: (updateNode: T, counters: estree.Identifier[]) => void,
      loopBody: estree.Node,
    ) {
      const counters: estree.Identifier[] = [];
      extractCounters(updateNode, counters);
      counters.forEach(counter => checkCounter(counter, loopBody as estree.BlockStatement));
    }

    function checkCounter(counter: estree.Identifier, block: estree.Node) {
      const variable = getVariableFromName(context, counter.name);
      if (!variable) {
        return;
      }
      variable.references.forEach(ref => {
        if (ref.isWrite() && isUsedInsideBody(ref.identifier, block)) {
          context.report({
            node: ref.identifier,
            message: toEncodedMessage(
              `Remove this assignment of "${counter.name}".`,
              [counter as TSESTree.Node],
              ["Counter variable update"],
            ),
          });
        }
      });
    }

    return {
      "ForStatement > BlockStatement": (node: estree.Node) => {
        const forLoop = getParent(context) as estree.ForStatement;
        if (forLoop.update) {
          checkLoop(forLoop.update, collectCountersFor, node);
        }
      },
      "ForInStatement > BlockStatement, ForOfStatement > BlockStatement": (node: estree.Node) => {
        const { left } = getParent(context) as estree.ForOfStatement | estree.ForInStatement;
        checkLoop(left, collectCountersForX, node);
      },
    };
  },
};

function collectCountersForX(
  updateExpression: estree.Pattern | estree.VariableDeclaration,
  counters: estree.Identifier[],
) {
  if (updateExpression.type === "VariableDeclaration") {
    updateExpression.declarations.forEach(decl => collectCountersForX(decl.id, counters));
  } else {
    resolveIdentifiers(updateExpression as TSESTree.Node, true).forEach(id => counters.push(id));
  }
}

function collectCountersFor(updateExpression: estree.Expression, counters: estree.Identifier[]) {
  let counter: estree.Node | null | undefined = undefined;

  if (updateExpression.type === "AssignmentExpression") {
    counter = updateExpression.left;
  } else if (updateExpression.type === "UpdateExpression") {
    counter = updateExpression.argument;
  } else if (updateExpression.type === "SequenceExpression") {
    updateExpression.expressions.forEach(e => collectCountersFor(e, counters));
  }

  if (counter && counter.type === "Identifier") {
    counters.push(counter);
  }
}

function isUsedInsideBody(id: estree.Identifier, loopBody: estree.Node) {
  const bodyRange = loopBody.range;
  return id.range && bodyRange && id.range[0] > bodyRange[0] && id.range[1] < bodyRange[1];
}
