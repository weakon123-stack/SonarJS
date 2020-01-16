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

import java.util.Collections;
import java.util.List;

import org.sonar.check.Rule;
import org.sonar.check.RuleProperty;
import org.sonar.javascript.checks.annotations.JavaScriptRule;
import org.sonar.javascript.checks.annotations.TypeScriptRule;

@JavaScriptRule
@TypeScriptRule
@Rule(key = "S117")
public class VariableNameCheck extends EslintBasedCheck {

  private static final String CAMEL_CASED = "^[_$A-Za-z][$A-Za-z0-9]*$";
  private static final String UPPER_CASED = "^[_$A-Z][_$A-Z0-9]+$";

  private static final String DEFAULT_FORMAT = CAMEL_CASED + "|" + UPPER_CASED;

  @RuleProperty(
      key = "format",
      description = "Regular expression used to check the names against.",
      defaultValue = "" + DEFAULT_FORMAT)
  public String format = DEFAULT_FORMAT;

  @Override
  public List<Object> configurations() {
    return Collections.singletonList(new FormatRuleProperty(format));
  }

  @Override
  public String eslintKey() {
    return "variable-name";
  }
}
