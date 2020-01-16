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
package org.sonar.javascript.se.sv;

import java.util.Optional;
import org.sonar.javascript.se.Constraint;
import org.sonar.javascript.se.ProgramState;
import org.sonar.plugins.javascript.api.tree.Tree.Kind;
import org.sonar.plugins.javascript.api.tree.expression.LiteralTree;

/**
 * This class represents symbolic value for literal (string, number and boolean).
 * Current implementation provides only truthy/falsy constraint for this symbolic value, thus we are not able to process numeric constraints.
 */
public class LiteralSymbolicValue implements SymbolicValue {

  private final LiteralTree literal;
  private final Constraint constraint;

  private LiteralSymbolicValue(LiteralTree literal) {
    this.literal = literal;
    this.constraint = getConstraint(literal);
  }

  public static SymbolicValue get(LiteralTree literal) {
    return new LiteralSymbolicValue(literal);
  }

  public LiteralTree getLiteral() {
    return literal;
  }

  @Override
  public Optional<ProgramState> constrainDependencies(ProgramState state, Constraint constraint) {
    if (baseConstraint(state).isIncompatibleWith(constraint)) {
      return Optional.empty();
    }
    return Optional.of(state);
  }

  @Override
  public Constraint baseConstraint(ProgramState state) {
    return constraint;
  }

  private static Constraint getConstraint(LiteralTree literal) {
    Constraint result = null;
    if (literal.is(Kind.BOOLEAN_LITERAL)) {
      result = "true".equals(literal.value()) ? Constraint.TRUE : Constraint.FALSE;
    }
    if (literal.is(Kind.STRING_LITERAL)) {
      result = literal.value().length() > 2 ? Constraint.TRUTHY_STRING_PRIMITIVE : Constraint.EMPTY_STRING_PRIMITIVE;
    }
    if (literal.is(Kind.NUMERIC_LITERAL)) {
      result = isZero(literal) ? Constraint.ZERO : Constraint.POSITIVE_NUMBER_PRIMITIVE;
    }

    if (literal.is(Kind.REGULAR_EXPRESSION_LITERAL)) {
      result = Constraint.REGEXP;
    }

    if (result != null) {
      return result;
    }
    throw new IllegalStateException("Unknown literal: " + literal);
  }

  private static boolean isZero(LiteralTree literal) {
    String stringValue = literal.value();

    if (stringValue.startsWith("0x")
      || stringValue.startsWith("0b")
      || stringValue.startsWith("0o")
      || stringValue.startsWith("0O")) {

      return allZero(stringValue.substring(2));
    }

    int exponentIndex = stringValue.indexOf('e');
    if (exponentIndex == -1) {
      exponentIndex = stringValue.indexOf('E');
    }
    if (exponentIndex > -1) {
      stringValue = stringValue.substring(0, exponentIndex);
    }
    return allZero(stringValue);
  }

  private static boolean allZero(String str) {
    for (int i = 0; i < str.length(); i++) {
      char c = str.charAt(i);
      if (c != '0' && c != '.') {
        return false;
      }
    }
    return true;
  }

  @Override
  public String toString() {
    return "LiteralSV " + literal.value();
  }
}
