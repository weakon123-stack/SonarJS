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
package org.sonar.javascript.tree.impl.declaration;

import com.google.common.collect.Iterators;
import java.util.Iterator;
import javax.annotation.Nullable;
import org.sonar.javascript.tree.impl.JavaScriptTree;
import org.sonar.plugins.javascript.api.tree.Tree;
import org.sonar.plugins.javascript.api.tree.declaration.SpecifierTree;
import org.sonar.plugins.javascript.api.tree.expression.IdentifierTree;
import org.sonar.plugins.javascript.api.tree.lexical.SyntaxToken;
import org.sonar.plugins.javascript.api.visitors.DoubleDispatchVisitor;

public class SpecifierTreeImpl extends JavaScriptTree implements SpecifierTree {

  private final Kind kind;
  private final SyntaxToken flowImportTypeOfTypeOfToken;
  private final IdentifierTree leftName;
  private final SyntaxToken asToken;
  private final IdentifierTree rightName;

  public SpecifierTreeImpl(Kind kind, @Nullable SyntaxToken flowImportTypeOfTypeOfToken, IdentifierTree leftName, SyntaxToken asToken, IdentifierTree rightName) {
    this.kind = kind;
    this.flowImportTypeOfTypeOfToken = flowImportTypeOfTypeOfToken;
    this.leftName = leftName;
    this.asToken = asToken;
    this.rightName = rightName;
  }

  public SpecifierTreeImpl(Kind kind, @Nullable SyntaxToken flowImportTypeOfTypeOfToken, IdentifierTree leftName) {
    this.kind = kind;
    this.flowImportTypeOfTypeOfToken = flowImportTypeOfTypeOfToken;
    this.leftName = leftName;
    this.asToken = null;
    this.rightName = null;
  }

  @Override
  public Kind getKind() {
    return kind;
  }

  @Override
  public Iterator<Tree> childrenIterator() {
    return Iterators.forArray(flowImportTypeOfTypeOfToken, leftName, asToken, rightName);
  }

  @Override
  public void accept(DoubleDispatchVisitor visitor) {
    visitor.visitSpecifier(this);
  }

  @Nullable
  @Override
  public SyntaxToken flowImportTypeOrTypeOfToken() {
    return flowImportTypeOfTypeOfToken;
  }

  @Override
  public IdentifierTree leftName() {
    return leftName;
  }

  @Nullable
  @Override
  public SyntaxToken asToken() {
    return asToken;
  }

  @Nullable
  @Override
  public IdentifierTree rightName() {
    return rightName;
  }
}
