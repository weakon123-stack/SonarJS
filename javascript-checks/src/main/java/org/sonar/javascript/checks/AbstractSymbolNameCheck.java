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

import com.google.common.base.Preconditions;
import java.util.LinkedList;
import java.util.List;
import org.sonar.plugins.javascript.api.symbols.Symbol;
import org.sonar.plugins.javascript.api.symbols.SymbolModel;
import org.sonar.plugins.javascript.api.symbols.Usage;
import org.sonar.plugins.javascript.api.visitors.DoubleDispatchVisitorCheck;

public abstract class AbstractSymbolNameCheck extends DoubleDispatchVisitorCheck {
  abstract List<String> illegalNames();

  protected List<Symbol> getIllegalSymbols() {
    SymbolModel symbolModel = getContext().getSymbolModel();
    List<Symbol> symbols = new LinkedList<>();
    for (String name : illegalNames()) {
      symbols.addAll(symbolModel.getSymbols(name));
    }
    return symbols;
  }

  protected void raiseIssuesOnDeclarations(Symbol symbol, String message) {
    Preconditions.checkArgument(!symbol.external());

    boolean issueRaised = false;
    for (Usage usage : symbol.usages()) {
      if (usage.isDeclaration()) {
        addIssue(usage.identifierTree(), message);
        issueRaised = true;
      }
    }

    if (!issueRaised) {
      addIssue(symbol.usages().iterator().next().identifierTree(), message);
    }

  }
}
