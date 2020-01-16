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
// https://jira.sonarsource.com/browse/RSPEC-2870

import { Rule } from "eslint";
import * as estree from "estree";
import { isRequiredParserServices } from "../utils/isRequiredParserServices";
import { getParent } from "eslint-plugin-sonarjs/lib/utils/nodes";
import { isArray } from "./utils";

const ArrayDeleteExpression =
  "UnaryExpression[operator='delete'] > MemberExpression[computed=true]";

export const rule: Rule.RuleModule = {
  create(context: Rule.RuleContext) {
    const services = context.parserServices;
    if (isRequiredParserServices(services)) {
      return {
        [ArrayDeleteExpression]: (node: estree.Node) => {
          const member = node as estree.MemberExpression;
          const object = member.object;
          if (isArray(object, services)) {
            raiseIssue(context);
          }
        },
      };
    }
    return {};
  },
};

function raiseIssue(context: Rule.RuleContext): void {
  const deleteKeyword = context.getSourceCode().getFirstToken(getParent(context)!);
  context.report({
    message: `Remove this use of "delete".`,
    loc: deleteKeyword!.loc,
  });
}
