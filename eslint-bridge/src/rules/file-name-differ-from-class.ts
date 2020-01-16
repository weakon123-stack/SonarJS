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
// https://jira.sonarsource.com/browse/RSPEC-3317

import { Rule, Scope } from "eslint";
import * as estree from "estree";
import { getVariableFromName } from "./utils";

export const rule: Rule.RuleModule = {
  create(context: Rule.RuleContext) {
    var isOnlyExport = true;
    var nameOfExported: string | undefined = undefined;

    return {
      ExportDefaultDeclaration: (node: estree.Node) => {
        const declaration = (node as estree.ExportDefaultDeclaration).declaration;
        if (declaration.type === "Identifier") {
          const variable = getVariableFromName(context, declaration.name);
          if (variable && variable.defs.length === 1) {
            const def = variable.defs[0];
            if (def.type === "ClassName" || def.type === "FunctionName" || isConst(def)) {
              nameOfExported = declaration.name;
            }
          }
        } else if (
          declaration.type === "ClassDeclaration" ||
          declaration.type === "FunctionDeclaration"
        ) {
          if (declaration.id) {
            nameOfExported = declaration.id.name;
          }
        }
      },
      "ExportAllDeclaration, ExportNamedDeclaration": () => {
        isOnlyExport = false;
      },
      "Program:exit": () => {
        if (isOnlyExport && nameOfExported) {
          const splittedFileName = context.getFilename().split(/[\\/]/);
          const fileName = splittedFileName[splittedFileName.length - 1].split(".")[0];
          if ("index" !== fileName && !sameName(nameOfExported, fileName)) {
            context.report({
              message: `Rename this file to "${nameOfExported}"`,
              loc: { line: 0, column: 0 },
            });
          }
        }
      },
    };
  },
};

function sameName(nameOfExported: string, fileName: string) {
  const normalizedFileName = fileName.replace(/_/g, "").replace(/-/g, "");
  const normalizedNameOfExported = nameOfExported.replace(/_/g, "").replace(/-/g, "");
  return normalizedNameOfExported.toLowerCase() === normalizedFileName.toLowerCase();
}

function isConst(def: Scope.Definition) {
  return def.type === "Variable" && def.parent && def.parent.kind === "const";
}
