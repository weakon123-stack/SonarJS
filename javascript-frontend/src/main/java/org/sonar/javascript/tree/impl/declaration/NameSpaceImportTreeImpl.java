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
import org.sonar.javascript.tree.impl.lexical.InternalSyntaxToken;
import org.sonar.plugins.javascript.api.tree.Tree;
import org.sonar.plugins.javascript.api.tree.declaration.NameSpaceImportTree;
import org.sonar.plugins.javascript.api.tree.expression.IdentifierTree;
import org.sonar.plugins.javascript.api.tree.lexical.SyntaxToken;
import org.sonar.plugins.javascript.api.visitors.DoubleDispatchVisitor;

public class NameSpaceImportTreeImpl extends JavaScriptTree implements NameSpaceImportTree {

  private final SyntaxToken starToken;
  private final SyntaxToken asToken;
  private final IdentifierTree localName;

  public NameSpaceImportTreeImpl(InternalSyntaxToken starToken, InternalSyntaxToken asToken, IdentifierTree localName) {
    this.starToken = starToken;
    this.asToken = asToken;
    this.localName = localName;

  }

  @Override
  public SyntaxToken starToken() {
    return starToken;
  }

  @Nullable
  @Override
  public SyntaxToken asToken() {
    return asToken;
  }

  @Nullable
  @Override
  public IdentifierTree localName() {
    return localName;
  }

  @Override
  public Kind getKind() {
    return Kind.NAME_SPACE_IMPORT;
  }

  @Override
  public Iterator<Tree> childrenIterator() {
    return Iterators.forArray(starToken, asToken, localName);
  }

  @Override
  public void accept(DoubleDispatchVisitor visitor) {
    visitor.visitNameSpaceImport(this);
  }
}
