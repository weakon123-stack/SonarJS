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
package org.sonar.javascript.checks;

import org.sonar.check.Rule;
import org.sonar.javascript.checks.annotations.JavaScriptRule;
import org.sonar.plugins.javascript.api.tree.expression.CallExpressionTree;

@JavaScriptRule
@Rule(key = "S2716")
public class UniversalSelectorCheck extends AbstractJQuerySelectorOptimizationCheck {

  private static final String MESSAGE = "Remove the use of this universal selector.";

  @Override
  protected void visitSelector(String selector, CallExpressionTree tree) {
    String[] parts = selector.split("[ >]");
    for (int i = 1; i < parts.length; i++) {
      if ("*".equals(parts[i])) {
        addIssue(tree, MESSAGE);
        return;
      }
    }
  }
}
