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
// https://jira.sonarsource.com/browse/RSPEC-4324

import { Rule } from "eslint";
import { TSESTree } from "@typescript-eslint/experimental-utils";
import {
  isRequiredParserServices,
  RequiredParserServices,
} from "../utils/isRequiredParserServices";
import * as estree from "estree";

type ReturnedExpression = estree.Expression | undefined | null;

const message = "Remove this return type or change it to a more specific.";

let ts: any;

export const rule: Rule.RuleModule = {
  create(context: Rule.RuleContext) {
    const services = context.parserServices;

    if (isRequiredParserServices(services)) {
      ts = require("typescript");
      const returnedExpressions: ReturnedExpression[][] = [];
      return {
        ReturnStatement(node: estree.Node) {
          if (returnedExpressions.length > 0) {
            returnedExpressions[returnedExpressions.length - 1].push(
              (node as estree.ReturnStatement).argument,
            );
          }
        },
        FunctionDeclaration: function() {
          returnedExpressions.push([]);
        },
        "FunctionDeclaration:exit": function(node: estree.Node) {
          const returnType = (node as TSESTree.FunctionDeclaration).returnType;
          if (
            returnType &&
            returnType.typeAnnotation.type === "TSAnyKeyword" &&
            returnedExpressions.length > 0 &&
            allReturnTypesEqual(returnedExpressions[returnedExpressions.length - 1], services)
          ) {
            context.report({
              message,
              loc: returnType.loc,
            });
          }
          returnedExpressions.pop();
        },
      };
    }
    return {};
  },
};

function allReturnTypesEqual(
  returns: ReturnedExpression[],
  services: RequiredParserServices,
): boolean {
  const firstReturnType = getTypeFromTreeNode(returns.pop(), services);
  if (!!firstReturnType && !!isPrimitiveType(firstReturnType)) {
    return returns.every(nextReturn => {
      const nextReturnType = getTypeFromTreeNode(nextReturn, services);
      return !!nextReturnType && nextReturnType.flags === firstReturnType.flags;
    });
  }
  return false;
}

function getTypeFromTreeNode(node: ReturnedExpression, services: RequiredParserServices) {
  const checker = services.program.getTypeChecker();
  return checker.getTypeAtLocation(services.esTreeNodeToTSNodeMap.get(node as TSESTree.Node));
}

function isPrimitiveType({ flags }: any) {
  return (
    flags & ts.TypeFlags.BooleanLike ||
    flags & ts.TypeFlags.NumberLike ||
    flags & ts.TypeFlags.StringLike ||
    flags & ts.TypeFlags.EnumLike
  );
}
