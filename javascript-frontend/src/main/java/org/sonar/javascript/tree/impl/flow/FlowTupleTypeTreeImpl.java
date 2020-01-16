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
package org.sonar.javascript.tree.impl.flow;

import com.google.common.base.Functions;
import com.google.common.collect.Iterators;
import java.util.Iterator;
import org.sonar.javascript.tree.impl.JavaScriptTree;
import org.sonar.plugins.javascript.api.tree.SeparatedList;
import org.sonar.plugins.javascript.api.tree.Tree;
import org.sonar.plugins.javascript.api.tree.flow.FlowTupleTypeTree;
import org.sonar.plugins.javascript.api.tree.flow.FlowTypeTree;
import org.sonar.plugins.javascript.api.tree.lexical.SyntaxToken;
import org.sonar.plugins.javascript.api.visitors.DoubleDispatchVisitor;

public class FlowTupleTypeTreeImpl extends JavaScriptTree implements FlowTupleTypeTree {

  private final SyntaxToken leftBracketToken;
  private final SeparatedList<FlowTypeTree> elements;
  private final SyntaxToken rightBracketToken;

  public FlowTupleTypeTreeImpl(SyntaxToken leftBracketToken, SeparatedList<FlowTypeTree> elements, SyntaxToken rightBracketToken) {
    this.leftBracketToken = leftBracketToken;
    this.elements = elements;
    this.rightBracketToken = rightBracketToken;
  }

  @Override
  public Kind getKind() {
    return Kind.FLOW_TUPLE_TYPE;
  }

  @Override
  public Iterator<Tree> childrenIterator() {
    return Iterators.concat(Iterators.singletonIterator(leftBracketToken), elements.elementsAndSeparators(Functions.identity()), Iterators.singletonIterator(rightBracketToken));
  }

  @Override
  public SyntaxToken leftBracketToken() {
    return leftBracketToken;
  }

  @Override
  public SeparatedList<FlowTypeTree> elements() {
    return elements;
  }

  @Override
  public SyntaxToken rightBracketToken() {
    return rightBracketToken;
  }

  @Override
  public void accept(DoubleDispatchVisitor visitor) {
    visitor.visitFlowTupleType(this);
  }
}
